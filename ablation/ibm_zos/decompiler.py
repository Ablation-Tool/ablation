import json
import re
from dataclasses import dataclass, field

from .callgraph import _memory_operand
from .io_utils import ensure_directory, write_text


@dataclass
class IRStatement:
    address: int
    text: str
    original: str


@dataclass
class IRBlock:
    start: int
    instructions: list
    successors: list[int] = field(default_factory=list)
    statements: list[IRStatement] = field(default_factory=list)
    condition: tuple | None = None
    branch_mask: int | None = None
    return_value: str = "r15"

    @property
    def terminator(self):
        return self.instructions[-1]


@dataclass
class Decompilation:
    entry_rva: int
    code_rva: int
    name: str | None
    pseudo_c: str
    block_count: int
    structured_loop_count: int
    unknown_statement_count: int
    stack_variables: list[str]
    complete: bool | None

    def to_dict(self):
        return self.__dict__.copy()


def _hex(value):
    return f"{value:#x}"


def _stack_name(displacement):
    return f"stack_m{-displacement:x}" if displacement < 0 else f"stack_{displacement:x}"


def _identifier(name, address):
    if not name:
        return f"fn_{address:x}"
    value = re.sub(r"[^A-Za-z0-9_]", "_", name)
    if value[0].isdigit():
        value = "fn_" + value
    return value[:96] + (f"_{address:x}" if len(value) > 96 else "")


def _branch_parts(cc, mask):
    if mask is None:
        return "cc_condition_unknown()"
    if mask == 0:
        return "0"
    if mask == 15:
        return "1"
    if cc is None:
        return f"cc_mask(0x{mask:x})"
    kind, left, right = cc
    if kind == "test":
        if mask == 8:
            return f"({left} == 0)"
        if mask == 14:
            return f"({left} != 0)"
        return f"test_cc({left}, 0x{mask:x})"
    if kind == "memcmp":
        if mask == 8:
            return f"({left} == 0)"
        if mask == 14:
            return f"({left} != 0)"
        return f"memcmp_cc({left}, 0x{mask:x})"
    signed = kind == "signed"
    cast = "int32_t" if signed else "uint32_t"
    terms = []
    if mask & 8:
        terms.append(f"{left} == {right}")
    if mask & 4:
        terms.append(f"({cast}){left} < ({cast}){right}")
    if mask & 2:
        terms.append(f"({cast}){left} > ({cast}){right}")
    if mask & 1:
        terms.append("cc_overflow()")
    return "(" + " || ".join(terms) + ")" if terms else "0"


def _negate(condition):
    return f"!({condition})"


class S390Decompiler:
    def __init__(self, image, recovery=None, call_graph=None):
        self.image = image
        self.recovery = recovery
        self.call_graph = call_graph
        self.stack_variables = set()
        self.unknown_statements = 0
        self.call_targets = {}
        if call_graph is not None:
            self.call_targets = {site.site_rva: site for site in call_graph.edges}

    def _memory(self, instruction, size):
        operand = _memory_operand(instruction)
        if operand is None and instruction.format == "SI":
            raw = instruction.data
            operand = (0, 0, raw[2] >> 4, ((raw[2] & 15) << 8) | raw[3])
        if operand is None:
            return f"MEM{size}(unknown)"
        _, index, base, displacement = operand
        if not index and base in (4, 13):
            name = _stack_name(displacement)
            self.stack_variables.add(name)
            return name
        terms = []
        if index:
            terms.append(f"r{index}")
        if base:
            terms.append(f"r{base}")
        if displacement or not terms:
            terms.append(_hex(displacement))
        return f"MEM{size}(" + " + ".join(terms) + ")"

    def _immediate(self, instruction):
        if instruction.format == "RI":
            return int.from_bytes(instruction.data[2:4], "big", signed=instruction.mnemonic not in ("tmlh", "tmll", "tmhh", "tmhl"))
        if instruction.format == "RIL":
            return int.from_bytes(instruction.data[2:6], "big", signed=instruction.mnemonic not in {
                "xihf", "xilf", "iihf", "iilf", "nihf", "nilf", "oihf", "oilf",
                "llihf", "llilf", "algfi", "alfi", "slgfi", "slfi", "clgfi", "clfi", "clih",
            })
        return None

    def _expression(self, instruction, registers):
        mnemonic = instruction.mnemonic
        raw = instruction.data
        operand = _memory_operand(instruction)
        if operand is not None:
            destination = operand[0]
            memory = self._memory(instruction, 64 if mnemonic in ("lg", "stg") else 32)
            if mnemonic in ("l", "lg", "ly", "lgf", "llgf"):
                registers[destination] = memory
                return True
            if mnemonic in ("la", "lay"):
                _, index, base, displacement = operand
                terms = []
                for register in (index, base):
                    if register:
                        terms.append(registers.get(register, f"r{register}"))
                if displacement or not terms:
                    terms.append(_hex(displacement))
                registers[destination] = "(" + " + ".join(terms) + ")"
                return True
            if mnemonic in ("st", "sty", "stg"):
                return IRStatement(instruction.address, f"{memory} = r{destination};", instruction.text())
            if mnemonic in ("sth", "stc"):
                memory = self._memory(instruction, 16 if mnemonic == "sth" else 8)
                return IRStatement(instruction.address, f"{memory} = r{destination};", instruction.text())
            if mnemonic in ("lh", "lgh", "ic"):
                size = 8 if mnemonic == "ic" else 16
                registers[destination] = self._memory(instruction, size)
                return True
            if mnemonic in ("a", "s", "al", "sl", "n", "o", "x", "ay", "sy", "aly", "sly", "ny", "oy", "xy"):
                operations = {"a": "+", "ay": "+", "al": "+", "aly": "+", "s": "-", "sy": "-", "sl": "-", "sly": "-", "n": "&", "ny": "&", "o": "|", "oy": "|", "x": "^", "xy": "^"}
                operation = operations[mnemonic]
                registers[destination] = f"({registers.get(destination, f'r{destination}')} {operation} {memory})"
                return True
            if mnemonic in ("c", "cl", "cg", "clg", "ch", "cgh", "cy", "cly", "cgf", "clgf"):
                unsigned = mnemonic in ("cl", "clg", "cly", "clgf")
                return IRStatement(instruction.address, "", instruction.text()), ("unsigned" if unsigned else "signed", f"r{destination}", memory)
            if mnemonic in ("stm", "stmg"):
                width = 64 if mnemonic == "stmg" else 32
                return IRStatement(instruction.address, f"store{width}_range({memory}, r{destination}, r{operand[1]});", instruction.text())
            if mnemonic in ("lm", "lmg"):
                width = 64 if mnemonic == "lmg" else 32
                return IRStatement(instruction.address, f"load{width}_range({memory}, r{destination}, r{operand[1]});", instruction.text())
            if mnemonic in ("clm", "clmh"):
                return IRStatement(instruction.address, "", instruction.text()), ("unsigned", f"CLM(r{destination}, 0x{operand[1]:x}, {memory})", "0")
            if mnemonic in ("icm", "icmh"):
                registers[destination] = f"ICM(r{destination}, 0x{operand[1]:x}, {memory})"
                return True
            if mnemonic in ("sll", "srl", "sra", "sla", "srdl", "slda", "srda"):
                operations = {"sll": "<<", "sla": "<<", "srl": ">>", "srdl": ">>", "sra": ">>", "srda": ">>", "slda": "<<"}
                registers[destination] = f"({registers.get(destination, f'r{destination}')} {operations[mnemonic]} ({instruction.operands.split(', ')[-1]}))"
                return True
        if instruction.format in ("RR", "RRE"):
            left, right = raw[1] >> 4, raw[1] & 15
            if mnemonic in ("balr", "basr") and right == 0:
                registers[left] = _hex(instruction.end)
                return True
            if mnemonic in ("lr", "lgr", "ltr", "ltgr"):
                registers[left] = registers.get(right, f"r{right}")
                return True
            operations = {"ar": "+", "alr": "+", "sr": "-", "slr": "-", "nr": "&", "or": "|", "xr": "^", "alcr": "+", "alcgr": "+"}
            if mnemonic in operations:
                registers[left] = f"({registers.get(left, f'r{left}')} {operations[mnemonic]} {registers.get(right, f'r{right}')})"
                return True
            if mnemonic in ("lcr", "lcgr"):
                registers[left] = f"(-{registers.get(right, f'r{right}')})"
                return True
            if mnemonic in ("cr", "clr", "cgr", "clgr"):
                kind = "unsigned" if mnemonic in ("clr", "clgr") else "signed"
                return IRStatement(instruction.address, "", instruction.text()), (kind, f"r{left}", f"r{right}")
        immediate = self._immediate(instruction)
        if immediate is not None and instruction.format in ("RI", "RIL"):
            register = raw[1] >> 4
            value = _hex(immediate)
            if mnemonic in ("lhi", "lghi", "lgfi", "llilf", "llihf", "llill", "llilh", "llihl", "llihh"):
                registers[register] = value
                return True
            operations = {"ahi": "+", "aghi": "+", "afi": "+", "agfi": "+", "alfi": "+", "algfi": "+", "slfi": "-", "slgfi": "-", "nilf": "&", "nill": "&", "oilf": "|", "oill": "|", "xilf": "^"}
            if mnemonic in operations:
                registers[register] = f"({registers.get(register, f'r{register}')} {operations[mnemonic]} {value})"
                return True
            if mnemonic in ("chi", "cghi", "cfi", "cgfi", "clfi", "clgfi", "cih", "clih"):
                unsigned = mnemonic in ("clfi", "clgfi", "clih")
                return IRStatement(instruction.address, "", instruction.text()), ("unsigned" if unsigned else "signed", f"r{register}", value)
            if mnemonic in ("tmlh", "tmll", "tmhh", "tmhl"):
                return IRStatement(instruction.address, "", instruction.text()), ("test", f"(r{register} & {value})", None)
        if mnemonic == "larl" and instruction.target is not None:
            registers[raw[1] >> 4] = _hex(instruction.target)
            return True
        if mnemonic == "mvi":
            return IRStatement(instruction.address, f"{self._memory(instruction, 8)} = {raw[1]:#x};", instruction.text())
        if mnemonic in ("ni", "oi", "xi"):
            operation = {"ni": "&", "oi": "|", "xi": "^"}[mnemonic]
            memory = self._memory(instruction, 8)
            return IRStatement(instruction.address, f"{memory} {operation}= {raw[1]:#x};", instruction.text())
        if mnemonic == "cli":
            return IRStatement(instruction.address, "", instruction.text()), ("unsigned", self._memory(instruction, 8), _hex(raw[1]))
        if mnemonic in ("mvc", "mvcle"):
            return IRStatement(instruction.address, f"memcpy({instruction.operands});", instruction.text())
        if mnemonic in ("clc", "clcl"):
            return IRStatement(instruction.address, "", instruction.text()), ("memcmp", f"memcmp({instruction.operands})", None)
        if mnemonic == "tm":
            return IRStatement(instruction.address, "", instruction.text()), ("test", f"({self._memory(instruction, 8)} & {raw[1]:#x})", None)
        return None

    def _statements(self, block):
        registers = {}
        condition = None
        statements = []

        def flush(instruction):
            for register, expression in sorted(registers.items()):
                if expression != f"r{register}":
                    statements.append(IRStatement(
                        instruction.address, f"r{register} = {expression};",
                        instruction.text() + " [recovered expression]",
                    ))
            registers.clear()

        for instruction in block.instructions:
            if instruction.flow in ("conditional_jump", "jump", "return"):
                continue
            if instruction.flow == "call":
                flush(instruction)
                site = self.call_targets.get(instruction.address)
                if site is not None:
                    target = f"fn_{site.target_rva:x}"
                    comment = f" /* {site.target_name} */" if site.target_name else ""
                    text = f"{target}(r1);{comment}"
                elif instruction.target is not None:
                    text = f"fn_{instruction.target:x}(r1);"
                else:
                    register = instruction.data[1] & 15 if instruction.format == "RR" else None
                    text = f"indirect_call(r{register});" if register is not None else "indirect_call();"
                statements.append(IRStatement(instruction.address, text, instruction.text()))
                continue
            if not instruction.known:
                self.unknown_statements += 1
                statements.append(IRStatement(instruction.address, f"UNKNOWN_0x{instruction.data.hex()}();", instruction.text()))
                continue
            generated = self._expression(instruction, registers)
            if isinstance(generated, tuple):
                statement, condition = generated
                if statement.text:
                    statements.append(statement)
            elif isinstance(generated, IRStatement):
                statements.append(generated)
            elif generated is None:
                statements.append(IRStatement(instruction.address, f"UNSUPPORTED_{instruction.mnemonic}(); /* {instruction.operands} */", instruction.text()))
        block.return_value = registers.get(15, "r15")
        if block.instructions:
            flush(block.instructions[-1])
        block.statements = statements
        block.condition = condition
        block.branch_mask = block.terminator.mask

    def _blocks(self, function):
        instructions = sorted(function.instructions, key=lambda item: item.address)
        if not instructions:
            return []
        starts = {instructions[0].address}
        for instruction in instructions:
            if instruction.target is not None:
                starts.add(instruction.target)
            if instruction.flow in ("conditional_jump", "jump", "return"):
                starts.add(instruction.end)
        starts = sorted(start for start in starts if instructions[0].address <= start <= instructions[-1].end)
        blocks = []
        for index, start in enumerate(starts):
            end = starts[index + 1] if index + 1 < len(starts) else instructions[-1].end + 1
            body = [instruction for instruction in instructions if start <= instruction.address < end]
            if body:
                blocks.append(IRBlock(start, body))
        by_address = {block.start: block for block in blocks}
        for block in blocks:
            terminator = block.terminator
            if terminator.flow == "return":
                successors = []
            elif terminator.flow == "jump":
                successors = [terminator.target] if terminator.target in by_address else []
            elif terminator.flow == "conditional_jump":
                successors = [target for target in (terminator.target, terminator.end) if target in by_address]
            else:
                successors = [terminator.end] if terminator.end in by_address else []
            block.successors = successors
            self._statements(block)
        return blocks

    def _emit_statements(self, block, indent):
        lines = []
        for statement in block.statements:
            if statement.text:
                lines.append(" " * indent + statement.text + f" /* {statement.original} */")
        return lines

    def _emit_goto(self, block, indent):
        terminator = block.terminator
        lines = []
        if terminator.flow == "return":
            lines.append(" " * indent + f"return {block.return_value}; /* {terminator.text()} */")
        elif terminator.flow == "conditional_jump":
            condition = _branch_parts(block.condition, block.branch_mask)
            if terminator.target in block.successors:
                lines.append(" " * indent + f"if ({condition}) goto loc_{terminator.target:x};")
            elif terminator.target is not None:
                lines.append(" " * indent + f"if ({condition}) external_branch({_hex(terminator.target)});")
            else:
                lines.append(" " * indent + f"if ({condition}) indirect_branch(); /* {terminator.operands} */")
            if block.successors.count(terminator.end):
                lines.append(" " * indent + f"goto loc_{terminator.end:x};")
        elif terminator.flow == "jump" and terminator.target in block.successors:
            lines.append(" " * indent + f"goto loc_{terminator.target:x};")
        elif terminator.flow == "jump" and terminator.target is not None:
            lines.append(" " * indent + f"external_branch({_hex(terminator.target)});")
        elif terminator.flow == "jump":
            lines.append(" " * indent + f"indirect_branch(); /* {terminator.operands} */")
        elif block.successors:
            lines.append(" " * indent + f"goto loc_{block.successors[0]:x};")
        return lines

    def _render(self, function, blocks):
        by_address = {block.start: block for block in blocks}
        predecessors = {block.start: set() for block in blocks}
        for block in blocks:
            for successor in block.successors:
                if successor in predecessors:
                    predecessors[successor].add(block.start)
        consumed = set()
        loops = 0
        lines = []
        for block in blocks:
            if block.start in consumed:
                continue
            terminator = block.terminator
            if (
                terminator.flow == "conditional_jump" and terminator.target == block.start
                and len(block.successors) == 2 and not predecessors[block.start] - {block.start}
            ):
                condition = _branch_parts(block.condition, block.branch_mask)
                lines.append("  do {")
                lines.extend(self._emit_statements(block, 4))
                lines.append(f"  }} while ({condition});")
                consumed.add(block.start)
                loops += 1
                continue
            body_target = terminator.target
            if terminator.flow == "conditional_jump":
                for body_address in block.successors:
                    body = by_address.get(body_address)
                    if body is None or body.start == block.start:
                        continue
                    if (
                        body.terminator.flow == "jump" and body.terminator.target == block.start
                        and len(body.successors) == 1
                        and not predecessors[block.start] - {block.start, body.start}
                        and not predecessors[body.start] - {block.start}
                    ):
                        condition = _branch_parts(block.condition, block.branch_mask)
                        if body_address != body_target:
                            condition = _negate(condition)
                        lines.append(f"  while ({condition}) {{")
                        lines.extend(self._emit_statements(block, 4))
                        lines.extend(self._emit_statements(body, 4))
                        lines.append("  }")
                        consumed.update((block.start, body.start))
                        loops += 1
                        break
            if block.start in consumed:
                continue
            lines.append(f"loc_{block.start:x}:")
            lines.extend(self._emit_statements(block, 2))
            lines.extend(self._emit_goto(block, 2))
            consumed.add(block.start)
        return lines, loops

    def decompile(self, function):
        self.stack_variables = set()
        self.unknown_statements = 0
        blocks = self._blocks(function)
        body, loop_count = self._render(function, blocks)
        arguments = []
        candidates = (1, 2, 3) if function.kind == "XPLINK_SAVE_STORE" else (1,)
        operands = "\n".join(instruction.operands for instruction in function.instructions)
        for register in candidates:
            if f"%r{register}" in operands:
                arguments.append(f"uintptr_t r{register}")
        name = _identifier(function.name, function.entry_rva)
        lines = [
            f"/* entry={function.entry_rva:#x} code={function.code_rva:#x} evidence={function.kind} confidence={function.confidence} */",
            "/* Prototype, expressions, and stack-shaped references are static estimates; verify linkage and types. */",
            f"uintptr_t {name}({', '.join(arguments) if arguments else 'void'}) {{",
        ]
        for variable in sorted(self.stack_variables):
            lines.append(f"  uintptr_t {variable}; /* stack-shaped reference, not a proven local */")
        lines.extend(body)
        if not any("return " in line for line in body):
            lines.append("  return r15; /* synthesized fallthrough; verify reachability */")
        lines.append("}")
        result = Decompilation(
            function.entry_rva, function.code_rva, function.name, "\n".join(lines) + "\n",
            len(blocks), loop_count, self.unknown_statements, sorted(self.stack_variables), function.complete,
        )
        return result

    def write(self, function, output_directory):
        result = self.decompile(function)
        output = ensure_directory(output_directory)
        write_text(output / f"fn_{function.entry_rva:x}.c", result.pseudo_c)
        write_text(output / f"fn_{function.entry_rva:x}.json", json.dumps(result.to_dict(), indent=2) + "\n")
        return result
