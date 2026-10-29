import json
from collections import Counter
from dataclasses import dataclass

from .io_utils import ensure_directory, write_text


@dataclass
class CallSite:
    caller_entry: int
    caller_name: str | None
    site_rva: int
    target_rva: int | None
    target_name: str | None
    evidence: str
    confidence: str

    def to_dict(self):
        return self.__dict__.copy()


@dataclass
class CallGraph:
    nodes: list[dict]
    edges: list[CallSite]
    unresolved: list[CallSite]

    def to_dict(self):
        evidence_counts = Counter(site.evidence for site in self.edges)
        return {
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "unresolved_call_count": len(self.unresolved),
            "evidence_counts": dict(evidence_counts),
            "nodes": self.nodes,
            "edges": [site.to_dict() for site in self.edges],
            "unresolved_calls": [site.to_dict() for site in self.unresolved],
        }

    def write(self, output_directory):
        output = ensure_directory(output_directory)
        result = self.to_dict()
        write_text(output / "callgraph.json", json.dumps(result, indent=2) + "\n")
        lines = []
        for site in self.edges:
            target = f"{site.target_rva:#x}" if site.target_rva is not None else "?"
            lines.append(
                f"{site.caller_entry:08x} {site.site_rva:08x} -> {target} "
                f"{site.target_name or '-'} ; {site.evidence} {site.confidence}\n"
            )
        for site in self.unresolved:
            lines.append(f"{site.caller_entry:08x} {site.site_rva:08x} -> unresolved ; {site.evidence}\n")
        write_text(output / "callgraph.txt", "".join(lines))
        return output


def _target_names(image, recovery):
    names = {}
    for symbol in image.symbols:
        if 0 <= symbol.address < len(image.text) and symbol.kind != "NAME":
            names.setdefault(symbol.address, symbol.name)
    for function in recovery.functions:
        if function.name:
            names.setdefault(function.entry_rva, function.name)
            names.setdefault(function.code_rva, function.name)
    return names


def _block_starts(function):
    starts = {function.code_rva}
    for instruction in function.instructions:
        if instruction.target is not None:
            starts.add(instruction.target)
        if instruction.flow in ("conditional_jump", "jump", "return"):
            starts.add(instruction.end)
    return starts


def _memory_operand(instruction):
    raw = instruction.data
    if instruction.format in ("RX", "RS", "RSE"):
        index = raw[1] & 15 if instruction.format == "RX" else 0
        return raw[1] >> 4, index, raw[2] >> 4, ((raw[2] & 15) << 8) | raw[3]
    if instruction.format == "RXY":
        displacement = (raw[4] << 12) | ((raw[2] & 15) << 8) | raw[3]
        if displacement & 0x80000:
            displacement -= 0x100000
        return raw[1] >> 4, raw[1] & 15, raw[2] >> 4, displacement
    return None


def _writes_register(instruction, register):
    if instruction.mnemonic in ("balr", "basr") and register == 14:
        return True
    operand = _memory_operand(instruction)
    if operand is not None and instruction.mnemonic in (
        "l", "lg", "ly", "lgf", "llgf", "la", "lay", "ic", "lh", "lgh",
    ):
        return operand[0] == register
    if instruction.format in ("RR", "RRE") and instruction.mnemonic not in ("cr", "clr", "cgr", "ltr", "ltgr"):
        return instruction.data[1] >> 4 == register
    if instruction.format == "RI" and instruction.mnemonic not in ("brc", "bras", "brct", "brctg", "brcth"):
        return instruction.data[1] >> 4 == register
    if instruction.format == "RIL" and instruction.mnemonic not in ("brcl", "brasl", "brcth"):
        return instruction.data[1] >> 4 == register
    return False


def _effective_address(operand, values):
    _, index_register, base, displacement = operand
    value = displacement
    for register in (index_register, base):
        if register:
            if register not in values:
                return None
            value += values[register][0]
    return value


def build_call_graph(image, recovery):
    names = _target_names(image, recovery)
    relocations = {
        item["rva"]: item for item in image.metadata.get("relocations", []) if item.get("resolved")
    }
    nodes = [
        {
            "entry_rva": function.entry_rva,
            "code_rva": function.code_rva,
            "name": function.name,
            "kind": function.kind,
            "confidence": function.confidence,
            "instruction_count": len(function.instructions),
        }
        for function in recovery.functions
    ]
    edges = []
    unresolved = []
    for function in recovery.functions:
        function.instructions.sort(key=lambda item: item.address)
        starts = _block_starts(function)
        values = {}
        for instruction in function.instructions:
            if instruction.address in starts:
                values = {}
            if instruction.flow == "call":
                target = instruction.target
                evidence = f"direct:{instruction.mnemonic}"
                confidence = "high"
                if target is None and instruction.format == "RR":
                    register = instruction.data[1] & 15
                    if register in values:
                        candidate, candidate_evidence, candidate_confidence = values[register]
                        if candidate_evidence.startswith(("rld:", "larl")) or candidate in names:
                            target = candidate
                            evidence = candidate_evidence
                            confidence = candidate_confidence
                if target is None:
                    unresolved.append(CallSite(
                        function.entry_rva, function.name, instruction.address,
                        None, None, f"indirect:{instruction.mnemonic}", "unresolved",
                    ))
                else:
                    edges.append(CallSite(
                        function.entry_rva, function.name, instruction.address,
                        target, names.get(target), evidence, confidence,
                    ))
                values = {}
                continue
            if instruction.format == "RR" and instruction.mnemonic in ("balr", "basr") and instruction.data[1] & 15 == 0:
                values[instruction.data[1] >> 4] = (instruction.end, "pc", "high")
                continue
            if instruction.mnemonic == "larl" and instruction.target is not None:
                values[instruction.data[1] >> 4] = (instruction.target, "larl", "high")
                continue
            if instruction.format in ("RR", "RRE") and instruction.mnemonic in ("lr", "lgr"):
                destination = instruction.data[1] >> 4
                source = instruction.data[1] & 15
                if source in values:
                    values[destination] = values[source]
                else:
                    values.pop(destination, None)
                continue
            operand = _memory_operand(instruction)
            if operand is not None and instruction.mnemonic in ("la", "lay"):
                destination = operand[0]
                address = _effective_address(operand, values)
                if address is None:
                    values.pop(destination, None)
                elif address in names:
                    values[destination] = (address, "la_symbol", "medium")
                else:
                    values[destination] = (address, "derived", "medium")
                continue
            if operand is not None and instruction.mnemonic in ("l", "lg", "ly", "lgf", "llgf"):
                destination = operand[0]
                address = _effective_address(operand, values)
                relocation = relocations.get(address) if address is not None else None
                if relocation and relocation["target_address"] is not None:
                    values[destination] = (relocation["target_address"], f"rld:{address:#x}", "high")
                else:
                    values.pop(destination, None)
                continue
            if instruction.mnemonic in ("lm", "lmg"):
                first = instruction.data[1] >> 4
                last = instruction.data[1] & 15
                for register in range(first, last + 1):
                    values.pop(register, None)
                continue
            for register in range(16):
                if _writes_register(instruction, register):
                    values.pop(register, None)
    edges.sort(key=lambda site: (site.caller_entry, site.site_rva, site.target_rva))
    unresolved.sort(key=lambda site: (site.caller_entry, site.site_rva))
    return CallGraph(nodes, edges, unresolved)
