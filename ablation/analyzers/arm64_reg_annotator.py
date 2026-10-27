"""AAPCS64-aware forward register annotation for AArch64 ELF binaries."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Tuple

import capstone
from capstone import arm64 as C_ARM64

from .reg_annotator import AnnotationResult, CallSite, RegVal

_ARM64_ARG_REGS = [f"x{i}" for i in range(8)]
_ARM64_CALLER_SAVED = {f"x{i}" for i in range(19)}


def _norm_reg(name: str) -> str:
    name = name.lower()
    if name == "wsp":
        return "sp"
    if name in ("wzr", "xzr"):
        return "xzr"
    if len(name) == 2 and name[0] == "w" and name[1].isdigit():
        return f"x{name[1]}"
    if len(name) == 3 and name[0] == "w" and name[1:].isdigit():
        return f"x{name[1:]}"
    return name


def _width_mask(name: str) -> int:
    return 0xFFFFFFFF if name.lower().startswith("w") else 0xFFFFFFFFFFFFFFFF


def _shift(operand) -> int:
    return int(getattr(getattr(operand, "shift", None), "value", 0))


def _reverse_bytes(value: int, width: int) -> int:
    return int.from_bytes(value.to_bytes(width, "little"), "big")


class ARM64RegAnnotator:
    """Track arguments to direct BL calls with a bounded linear symbolic pass."""

    def __init__(self, data: bytes, base: int, strings: Dict[int, str], plt: Dict[int, str]):
        self._data = data
        self._base = base
        self._strings = strings
        self._plt = plt
        self._arg_regs = list(_ARM64_ARG_REGS)
        self._sections: List[Tuple[int, int, bytes]] = []
        try:
            import lief

            binary = lief.parse(data)
            if isinstance(binary, lief.ELF.Binary):
                for section in binary.sections:
                    if section.size:
                        content = bytes(section.content)
                        va = int(section.virtual_address)
                        self._sections.append((va, va + len(content), content))
        except Exception:
            pass

    @classmethod
    def from_context(cls, ctx) -> "ARM64RegAnnotator":
        data = Path(ctx.path).read_bytes()
        return cls(data, ctx.base_va, ctx.strings, ctx.plt)

    @classmethod
    def from_path(cls, path: str) -> "ARM64RegAnnotator":
        from .binary_context import BinaryContext

        return cls.from_context(BinaryContext.load_or_build(path))

    def annotate_calls(
        self,
        va: int,
        end_va: int,
        window: int = 2048,
        seed_args: bool = True,
    ) -> AnnotationResult:
        size = min(end_va - va, window) if end_va > va else window
        chunk = self._read(va, size)
        if not chunk:
            return AnnotationResult(func_va=va, func_end_va=end_va, calls=[], reg_trace=[])

        arch = getattr(capstone, "CS_ARCH_AARCH64", None) or capstone.CS_ARCH_ARM64
        cs = capstone.Cs(arch, capstone.CS_MODE_ARM)
        cs.detail = True
        cs.skipdata = True

        state: Dict[str, RegVal] = {}
        memory: Dict[Tuple[str, int], RegVal] = {}
        if seed_args:
            for index, reg in enumerate(_ARM64_ARG_REGS):
                state[reg] = RegVal.arg(index)

        calls: List[CallSite] = []
        reg_trace: List[Tuple[int, str, RegVal]] = []

        def assign(reg: str, value: RegVal) -> None:
            state[reg] = value
            reg_trace.append((insn.address, reg, value))

        def source_value(reg_id: int) -> RegVal:
            reg = _norm_reg(insn.reg_name(reg_id))
            if reg == "xzr":
                return RegVal.zero()
            return state.get(reg, RegVal.unknown())

        def address_value(address: int) -> RegVal:
            string = self._strings.get(address)
            return RegVal.string(string) if string is not None else RegVal.const(address)

        def memory_key(operand) -> Optional[Tuple[str, int]]:
            if operand.type != C_ARM64.ARM64_OP_MEM or operand.mem.index:
                return None
            return _norm_reg(insn.reg_name(operand.mem.base)), int(operand.mem.disp)

        def memory_description(key: Tuple[str, int]) -> str:
            base, displacement = key
            base_value = state.get(base)
            if base_value and base_value.kind == "const":
                return f"0x{base_value.int_val + displacement:x}"
            sign = "+" if displacement >= 0 else "-"
            return f"{base}{sign}{abs(displacement):#x}"

        for insn in cs.disasm(chunk, va):
            if insn.address >= end_va:
                break
            mnemonic = insn.mnemonic.lower()
            try:
                operands = insn.operands
            except Exception:
                operands = []

            if mnemonic in ("bl", "blr") and operands:
                if mnemonic == "bl" and operands[0].type == C_ARM64.ARM64_OP_IMM:
                    target = operands[0].imm
                    target_name = self._plt.get(target, f"0x{target:x}")
                elif mnemonic == "blr" and operands[0].type == C_ARM64.ARM64_OP_REG:
                    target_value = source_value(operands[0].reg)
                    if target_value.kind == "const":
                        target = target_value.int_val
                        target_name = self._plt.get(target, f"0x{target:x}")
                    else:
                        target = 0
                        target_name = f"blr {insn.reg_name(operands[0].reg)}"
                else:
                    continue
                args = {reg: state.get(reg, RegVal.unknown()) for reg in _ARM64_ARG_REGS}
                calls.append(CallSite(insn.address, target, target_name, args))
                for reg in _ARM64_CALLER_SAVED:
                    state[reg] = RegVal.ret(target_name) if reg == "x0" else RegVal.unknown()
                continue

            if mnemonic in ("mov", "movz", "movn", "movk") and len(operands) >= 2:
                if operands[0].type != C_ARM64.ARM64_OP_REG:
                    continue
                destination_name = insn.reg_name(operands[0].reg)
                destination = _norm_reg(destination_name)
                shift = _shift(operands[1])
                if mnemonic == "mov" and operands[1].type == C_ARM64.ARM64_OP_IMM:
                    value = RegVal.const(operands[1].imm & _width_mask(destination_name))
                elif mnemonic == "mov" and operands[1].type == C_ARM64.ARM64_OP_REG:
                    source = _norm_reg(insn.reg_name(operands[1].reg))
                    value = RegVal.zero() if source == "xzr" else RegVal.copy(source, state.get(source))
                elif mnemonic == "movz" and operands[1].type == C_ARM64.ARM64_OP_IMM:
                    value = RegVal.const((operands[1].imm << shift) & _width_mask(destination_name))
                elif mnemonic == "movn" and operands[1].type == C_ARM64.ARM64_OP_IMM:
                    value = RegVal.const(~(operands[1].imm << shift) & _width_mask(destination_name))
                elif mnemonic == "movk" and operands[1].type == C_ARM64.ARM64_OP_IMM:
                    previous = state.get(destination)
                    if previous and previous.kind == "const":
                        mask = _width_mask(destination_name)
                        replaced = (previous.int_val & ~(0xFFFF << shift)) | (operands[1].imm << shift)
                        value = RegVal.const(replaced & mask)
                    else:
                        value = RegVal.unknown()
                else:
                    value = RegVal.unknown()
                assign(destination, value)
                continue

            if mnemonic in ("adrp", "adr") and len(operands) == 2:
                if operands[0].type == C_ARM64.ARM64_OP_REG and operands[1].type == C_ARM64.ARM64_OP_IMM:
                    assign(_norm_reg(insn.reg_name(operands[0].reg)), address_value(operands[1].imm))
                    continue

            if mnemonic in ("add", "sub", "lsl", "lsr", "and") and len(operands) >= 3:
                if (
                    operands[0].type == C_ARM64.ARM64_OP_REG
                    and operands[1].type == C_ARM64.ARM64_OP_REG
                    and operands[2].type == C_ARM64.ARM64_OP_IMM
                ):
                    destination = _norm_reg(insn.reg_name(operands[0].reg))
                    source = _norm_reg(insn.reg_name(operands[1].reg))
                    previous = state.get(source)
                    immediate = operands[2].imm
                    if previous and previous.kind == "const":
                        if mnemonic == "add":
                            result = previous.int_val + immediate
                        elif mnemonic == "sub":
                            result = previous.int_val - immediate
                        elif mnemonic == "lsl":
                            result = previous.int_val << immediate
                        elif mnemonic == "lsr":
                            result = previous.int_val >> immediate
                        else:
                            result = previous.int_val & immediate
                        assign(destination, address_value(result))
                    else:
                        assign(destination, RegVal.unknown())
                    if destination == "sp":
                        memory = {key: value for key, value in memory.items() if key[0] != "sp"}
                    continue

            if mnemonic in ("rev", "rev16", "rev32") and len(operands) == 2:
                if operands[0].type == C_ARM64.ARM64_OP_REG and operands[1].type == C_ARM64.ARM64_OP_REG:
                    destination = _norm_reg(insn.reg_name(operands[0].reg))
                    previous = source_value(operands[1].reg)
                    if previous.kind == "const":
                        if mnemonic == "rev":
                            width = 4 if insn.reg_name(operands[0].reg).startswith("w") else 8
                            result = _reverse_bytes(previous.int_val, width)
                        elif mnemonic == "rev16":
                            width = 4 if insn.reg_name(operands[0].reg).startswith("w") else 8
                            raw = previous.int_val.to_bytes(width, "little")
                            result = int.from_bytes(
                                b"".join(raw[index:index + 2][::-1] for index in range(0, width, 2)),
                                "little",
                            )
                        else:
                            raw = previous.int_val.to_bytes(8, "little")
                            result = int.from_bytes(raw[:4][::-1] + raw[4:][::-1], "little")
                        assign(destination, RegVal.const(result))
                    else:
                        assign(destination, RegVal.unknown())
                    continue

            if mnemonic.startswith(("ldr", "ldur")) and len(operands) >= 2:
                if operands[0].type == C_ARM64.ARM64_OP_REG:
                    key = memory_key(operands[1])
                    if key is not None:
                        value = memory.get(key) or RegVal.mem(memory_description(key))
                        assign(_norm_reg(insn.reg_name(operands[0].reg)), value)
                        continue

            if mnemonic.startswith(("str", "stur")) and len(operands) >= 2:
                if operands[0].type == C_ARM64.ARM64_OP_REG:
                    key = memory_key(operands[1])
                    if key is not None:
                        memory[key] = source_value(operands[0].reg)
                        continue

            try:
                for reg_id in insn.regs_write:
                    destination = _norm_reg(insn.reg_name(reg_id))
                    if destination in state:
                        state[destination] = RegVal.unknown()
            except Exception:
                pass

        return AnnotationResult(va, end_va, calls, reg_trace)

    def _read(self, va: int, size: int) -> bytes:
        if size <= 0:
            return b""
        for start, end, content in self._sections:
            offset = va - start
            if 0 <= offset < len(content):
                return content[offset:offset + size]
        offset = va - self._base
        if offset < 0 or offset >= len(self._data):
            return b""
        return self._data[offset:offset + size]
