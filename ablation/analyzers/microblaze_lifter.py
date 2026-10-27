"""Conservative structural pseudo-C lifting for recovered MicroBlaze CFGs."""

from __future__ import annotations

from typing import Optional

from .microblaze_cfg import MicroBlazeFunction, MicroBlazeRecovery
from .microblaze_decoder import MicroBlazeInsn


MAX_LIFT_BLOCKS = 4096
MAX_LIFT_INSTRUCTIONS = 100_000


def _reg(value: Optional[int]) -> str:
    return f"r{value}" if value is not None else "r?"


def _unsigned(value: int) -> str:
    return f"0x{value & 0xFFFFFFFF:x}"


def _address(insn: MicroBlazeInsn) -> str:
    if insn.rb is not None:
        return f"({_reg(insn.ra)} + {_reg(insn.rb)})"
    immediate = insn.imm or 0
    return f"({_reg(insn.ra)} + {immediate})" if immediate else _reg(insn.ra)


class MicroBlazeLifter:
    def __init__(
        self,
        recovery: MicroBlazeRecovery,
        *,
        function_names: Optional[dict[int, str]] = None,
        max_blocks: int = MAX_LIFT_BLOCKS,
        max_instructions: int = MAX_LIFT_INSTRUCTIONS,
    ) -> None:
        if max_blocks < 1 or max_instructions < 1:
            raise ValueError("lift limits must be positive")
        self.recovery = recovery
        self.function_names = function_names or {}
        self.max_blocks = max_blocks
        self.max_instructions = max_instructions

    def _name(self, address: int) -> str:
        return self.function_names.get(address, f"sub_{address:08x}")

    def lift_function(self, entry: int) -> str:
        function = self.recovery.functions.get(entry)
        if function is None:
            raise ValueError(f"no recovered MicroBlaze function at {entry:#x}")
        if len(function.blocks) > self.max_blocks:
            raise ValueError(f"function exceeds {self.max_blocks} lifted blocks")
        if len(function.instructions) > self.max_instructions:
            raise ValueError(f"function exceeds {self.max_instructions} lifted instructions")
        return self._emit_function(function)

    def lift_recovery(self) -> str:
        if sum(len(function.blocks) for function in self.recovery.functions.values()) > self.max_blocks:
            raise ValueError(f"recovery exceeds {self.max_blocks} lifted blocks")
        if len(self.recovery.code) > self.max_instructions:
            raise ValueError(f"recovery exceeds {self.max_instructions} lifted instructions")
        return "\n\n".join(self._emit_function(self.recovery.functions[entry]) for entry in sorted(self.recovery.functions))

    def _emit_function(self, function: MicroBlazeFunction) -> str:
        lines = [
            f"// MicroBlaze structural pseudo-C for {self._name(function.entry)}; no SSA or type recovery",
            f"uint32_t {self._name(function.entry)}(uint32_t arg0, uint32_t arg1, uint32_t arg2, "
            "uint32_t arg3, uint32_t arg4, uint32_t arg5) {",
            "  // r1=sp r3=return r5-r10=arg0-arg5 r15=link r0=zero",
        ]
        for block in function:
            lines.append(f"loc_{block.start:08x}:")
            index = 0
            while index < len(block.insns):
                insn = block.insns[index]
                if insn.delay_slot and index + 1 < len(block.insns):
                    slot = block.insns[index + 1]
                    self._emit_linear(slot, lines)
                    self._emit_control(insn, block.succs, lines)
                    index += 2
                else:
                    if insn.flow == "linear":
                        self._emit_linear(insn, lines)
                    else:
                        self._emit_control(insn, block.succs, lines)
                    index += 1
        lines.append("}")
        return "\n".join(lines)

    @staticmethod
    def _statement(lines: list[str], insn: MicroBlazeInsn, text: str) -> None:
        if text:
            lines.append(f"  /* {insn.address:08x} */ {text}")

    def _emit_linear(self, insn: MicroBlazeInsn, lines: list[str]) -> None:
        self._statement(lines, insn, self._linear(insn))

    def _linear(self, insn: MicroBlazeInsn) -> str:
        m = insn.mnemonic
        rd, ra, rb = _reg(insn.rd), _reg(insn.ra), _reg(insn.rb)
        if m in ("imm", "nop") or (
            insn.rd == 0 and m not in ("put", "mbar") and not m.startswith(("sb", "sh", "sw"))
        ):
            return ""

        binary = {
            "add": "+", "addk": "+", "addi": "+", "addik": "+",
            "or": "|", "ori": "|", "and": "&", "andi": "&",
            "xor": "^", "xori": "^",
        }
        if m in binary:
            rhs = rb if m in ("add", "addk", "or", "and", "xor") else _unsigned(insn.imm or 0)
            return f"{rd} = {ra} {binary[m]} {rhs};"
        carry_binary = {"addc": "+", "addkc": "+", "addic": "+", "addikc": "+"}
        if m in carry_binary:
            rhs = rb if m in ("addc", "addkc") else _unsigned(insn.imm or 0)
            return f"{rd} = {ra} + {rhs} + carry_in;"
        if m in ("rsub", "rsubk"):
            return f"{rd} = {rb} - {ra};"
        if m in ("rsubi", "rsubik"):
            return f"{rd} = {_unsigned(insn.imm or 0)} - {ra};"
        if m in ("rsubc", "rsubkc"):
            return f"{rd} = {rb} - {ra} + carry_in;"
        if m in ("rsubic", "rsubikc"):
            return f"{rd} = {_unsigned(insn.imm or 0)} - {ra} + carry_in;"
        if m == "andn":
            return f"{rd} = {ra} & ~{rb};"
        if m == "andni":
            return f"{rd} = {ra} & ~{_unsigned(insn.imm or 0)};"
        if m == "mul":
            return f"{rd} = (int32_t){ra} * (int32_t){rb};"
        if m == "muli":
            return f"{rd} = (int32_t){ra} * {insn.imm or 0};"
        if m in ("mulh", "mulhsu", "mulhu"):
            return f"{rd} = {m}_high({ra}, {rb});"
        if m in ("idiv", "idivu"):
            cast = "int32_t" if m == "idiv" else "uint32_t"
            return f"{rd} = ({cast}){rb} / ({cast}){ra};"
        if m == "addk" and insn.rd is not None:
            return f"{rd} = {ra} + {rb};"

        widths = {"lbu": 8, "lhu": 16, "lw": 32, "lbui": 8, "lhui": 16, "lwi": 32}
        base_m = m.rstrip("earx") if m not in widths else m
        if base_m in widths:
            return f"{rd} = *(uint{widths[base_m]}_t *){_address(insn)};"
        store_widths = {"sb": 8, "sh": 16, "sw": 32, "sbi": 8, "shi": 16, "swi": 32}
        base_m = m.rstrip("earx") if m not in store_widths else m
        if base_m in store_widths:
            return f"*(uint{store_widths[base_m]}_t *){_address(insn)} = {rd};"

        if m in ("bsrli", "bsrai", "bslli", "bsrl", "bsra", "bsll"):
            operation = "<<" if m.endswith("lli") or m == "bsll" else ">>"
            rhs = str(insn.imm or 0) if m.endswith("i") else rb
            value = f"(int32_t){ra}" if m in ("bsrai", "bsra") else ra
            return f"{rd} = {value} {operation} {rhs};"
        if m in ("bsefi", "bsifi"):
            return f"{rd} = {m}({ra}, {insn.imm or 0});"
        if m in ("cmp", "cmpu"):
            cast = "int32_t" if m == "cmp" else "uint32_t"
            return f"{rd} = ({cast}){rb} - ({cast}){ra};"
        if m in ("pcmpbf", "pcmpeq", "pcmpne"):
            return f"{rd} = {m}({ra}, {rb});"

        unary = {
            "sra": "(int32_t){0} >> 1", "src": "rotate_right_carry({0})",
            "srl": "{0} >> 1", "sext8": "(int8_t){0}", "sext16": "(int16_t){0}",
            "clz": "count_leading_zeros({0})", "swapb": "byte_swap({0})",
            "swaph": "halfword_swap({0})",
        }
        if m in unary:
            return f"{rd} = {unary[m].format(ra)};"
        if m == "mfs":
            return f"{rd} = spr_{insn.imm or 0:x};"
        if m == "mts":
            return f"spr_{insn.imm or 0:x} = {ra};"
        if m == "msrset":
            return f"{rd} = msr | {_unsigned(insn.imm or 0)}; msr = {rd};"
        if m == "msrclr":
            return f"{rd} = msr & ~{_unsigned(insn.imm or 0)}; msr = {rd};"
        if m == "get":
            return f"{rd} = fsl_get({insn.imm or 0});"
        if m == "put":
            return f"fsl_put({insn.imm or 0}, {ra});"
        if m == "mbar":
            return f"memory_barrier({insn.imm or 0});"
        return f"/* unlifted: {m} {insn.operands} */"

    def _emit_control(self, insn: MicroBlazeInsn, successors: list[int], lines: list[str]) -> None:
        m = insn.mnemonic
        if insn.flow == "call":
            target = self._name(insn.target) if insn.target is not None else f"indirect_call_{_reg(insn.rb)}"
            args = "r5, r6, r7, r8, r9, r10"
            self._statement(lines, insn, f"r3 = {target}({args});")
            return
        if insn.flow == "return":
            self._statement(lines, insn, "return r3;")
            return
        if insn.flow == "trap":
            self._statement(lines, insn, f"trap({_unsigned(insn.imm or 0)});")
            return
        if insn.flow == "jump":
            if insn.target is not None:
                text = f"goto loc_{insn.target:08x};"
            elif successors:
                targets = ", ".join(f"loc_{address:08x}" for address in dict.fromkeys(successors))
                text = f"jump_table({_reg(insn.rb)}, {targets});"
            else:
                text = f"indirect_jump_{_reg(insn.rb)}(); /* unresolved */"
            self._statement(lines, insn, text)
            return
        if insn.flow == "conditional":
            condition = {
                "beq": "== 0", "bne": "!= 0", "blt": "< 0",
                "ble": "<= 0", "bgt": "> 0", "bge": ">= 0",
            }.get(m.rstrip("id"), "unknown_condition")
            left = f"(int32_t){_reg(insn.ra)}" if m.rstrip("id") not in ("beq", "bne") else _reg(insn.ra)
            if insn.target is not None:
                text = f"if ({left} {condition}) goto loc_{insn.target:08x};"
                fallthrough = next((address for address in successors if address != insn.target), None)
                if fallthrough is not None:
                    text += f" else goto loc_{fallthrough:08x};"
            else:
                text = f"/* unresolved conditional branch: {m} {insn.operands} */"
            self._statement(lines, insn, text)
            return
        self._statement(lines, insn, f"/* unlifted control flow: {m} {insn.operands} */")
