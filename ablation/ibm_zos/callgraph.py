import json
from collections import Counter
from dataclasses import dataclass, field

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
    external_calls: list[CallSite] = field(default_factory=list)
    binder_links: list[dict] = field(default_factory=list)

    def to_dict(self):
        evidence_counts = Counter(site.evidence for site in self.edges)
        return {
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "unresolved_call_count": len(self.unresolved),
            "external_call_count": len(self.external_calls),
            "binder_link_count": len(self.binder_links),
            "evidence_counts": dict(evidence_counts),
            "nodes": self.nodes,
            "edges": [site.to_dict() for site in self.edges],
            "unresolved_calls": [site.to_dict() for site in self.unresolved],
            "external_calls": [site.to_dict() for site in self.external_calls],
            "binder_links": self.binder_links,
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
        for site in self.external_calls:
            lines.append(f"{site.caller_entry:08x} {site.site_rva:08x} -> external {site.target_name} ; {site.evidence}\n")
        for link in self.binder_links:
            lines.append(f"{link['site_rva']:08x} -> {link['target_name']} @{link['dll']} ; {link['match']}\n")
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
        operand_byte = 1 if instruction.format == "RR" else 3
        return instruction.data[operand_byte] >> 4 == register
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


def _return_summaries(recovery, relocations):
    summaries = {}
    for function in recovery.functions:
        if function.complete is not True:
            continue
        instructions = sorted(function.instructions, key=lambda item: item.address)
        if not instructions or any(not item.known or item.flow in ("call", "conditional_jump", "jump") for item in instructions):
            continue
        if sum(item.flow == "return" for item in instructions) != 1:
            continue
        values = {}
        returns = []
        for instruction in instructions:
            if instruction.flow == "return":
                if 15 in values:
                    returns.append(values[15])
                continue
            if instruction.format == "RR" and instruction.mnemonic in ("balr", "basr") and instruction.data[1] & 15 == 0:
                values[instruction.data[1] >> 4] = instruction.end
                continue
            if instruction.mnemonic == "larl" and instruction.target is not None:
                values[instruction.data[1] >> 4] = instruction.target
                continue
            if instruction.format in ("RR", "RRE") and instruction.mnemonic in ("lr", "lgr"):
                encoded = instruction.data[1] if instruction.format == "RR" else instruction.data[3]
                destination = encoded >> 4
                source = encoded & 15
                if source in values:
                    values[destination] = values[source]
                else:
                    values.pop(destination, None)
                continue
            if instruction.format in ("RI", "RIL") and instruction.mnemonic in (
                "lhi", "lghi", "lgfi", "llilf", "llihf", "llill", "llilh", "llihl", "llihh",
            ):
                signed = instruction.mnemonic in ("lhi", "lghi", "lgfi")
                values[instruction.data[1] >> 4] = int.from_bytes(instruction.data[2:], "big", signed=signed)
                continue
            operand = _memory_operand(instruction)
            if operand is not None and instruction.mnemonic in ("la", "lay"):
                destination = operand[0]
                address = _effective_address(operand, values)
                if address is None:
                    values.pop(destination, None)
                else:
                    values[destination] = address
                continue
            if operand is not None and instruction.mnemonic in ("l", "lg", "ly", "lgf", "llgf"):
                destination = operand[0]
                address = _effective_address(operand, values)
                relocation = relocations.get(address) if address is not None else None
                if relocation and relocation["target_address"] is not None:
                    values[destination] = relocation["target_address"]
                else:
                    values.pop(destination, None)
                continue
            if instruction.mnemonic in ("lm", "lmg"):
                for register in range(instruction.data[1] >> 4, (instruction.data[1] & 15) + 1):
                    values.pop(register, None)
                continue
            for register in range(16):
                if _writes_register(instruction, register):
                    values.pop(register, None)
        if len(returns) == 1:
            summaries[function.entry_rva] = returns[0]
            summaries[function.code_rva] = returns[0]
    return summaries


def _binder_links(edges, external_calls, decks):
    from .sid import normalize_name

    symbols = {}
    for deck in decks:
        for statement in deck.statements:
            for name in {statement.symbol, statement.demangled}:
                normalized = normalize_name(name)
                if normalized:
                    symbols.setdefault(normalized, []).append((deck, statement))
    links = []
    for site in [*edges, *external_calls]:
        normalized = normalize_name(site.target_name)
        if not normalized or normalized not in symbols:
            continue
        for deck, statement in symbols[normalized]:
            links.append({
                "caller_entry": site.caller_entry,
                "site_rva": site.site_rva,
                "target_rva": site.target_rva,
                "target_name": site.target_name,
                "dll": statement.dll,
                "side_deck": deck.source_name,
                "symbol": statement.symbol,
                "demangled": statement.demangled,
                "kind": statement.kind,
                "match": "normalized_name",
            })
    return links


def build_call_graph(image, recovery, decks=()):
    names = _target_names(image, recovery)
    all_relocations = {
        item["rva"]: item for item in image.metadata.get("relocations", [])
    }
    relocations = {rva: item for rva, item in all_relocations.items() if item.get("resolved")}
    external_relocations = {rva: item for rva, item in all_relocations.items() if not item.get("resolved")}
    summaries = _return_summaries(recovery, relocations)
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
    external_calls = []
    for function in recovery.functions:
        function.instructions.sort(key=lambda item: item.address)
        starts = _block_starts(function)
        values = {}
        external_values = {}
        for instruction in function.instructions:
            if instruction.address in starts:
                values = {}
                external_values = {}
            if instruction.flow == "call":
                target = instruction.target
                evidence = f"direct:{instruction.mnemonic}"
                confidence = "high"
                if target is None and instruction.format == "RR":
                    register = instruction.data[1] & 15
                    if register in values:
                        candidate, candidate_evidence, candidate_confidence = values[register]
                        if candidate_evidence.startswith(("rld:", "larl", "summary:")) or candidate in names:
                            target = candidate
                            evidence = candidate_evidence
                            confidence = candidate_confidence
                    if target is None and register in external_values:
                        address, external = external_values[register]
                        external_calls.append(CallSite(
                            function.entry_rva, function.name, instruction.address, None,
                            external.get("target_name"), f"external_rld:{address:#x}", "unresolved",
                        ))
                if target is None and (
                    instruction.format != "RR" or instruction.data[1] & 15 not in external_values
                ):
                    unresolved.append(CallSite(
                        function.entry_rva, function.name, instruction.address,
                        None, None, f"indirect:{instruction.mnemonic}", "unresolved",
                    ))
                elif target is not None:
                    edges.append(CallSite(
                        function.entry_rva, function.name, instruction.address,
                        target, names.get(target), evidence, confidence,
                    ))
                if target in summaries:
                    values = {15: (summaries[target], f"summary:{target:#x}", "high")}
                else:
                    values = {}
                external_values = {}
                continue
            if instruction.format == "RR" and instruction.mnemonic in ("balr", "basr") and instruction.data[1] & 15 == 0:
                values[instruction.data[1] >> 4] = (instruction.end, "pc", "high")
                external_values.pop(instruction.data[1] >> 4, None)
                continue
            if instruction.mnemonic == "larl" and instruction.target is not None:
                values[instruction.data[1] >> 4] = (instruction.target, "larl", "high")
                external_values.pop(instruction.data[1] >> 4, None)
                continue
            if instruction.format in ("RR", "RRE") and instruction.mnemonic in ("lr", "lgr"):
                encoded = instruction.data[1] if instruction.format == "RR" else instruction.data[3]
                destination = encoded >> 4
                source = encoded & 15
                if source in values:
                    values[destination] = values[source]
                else:
                    values.pop(destination, None)
                external_values.pop(destination, None)
                continue
            operand = _memory_operand(instruction)
            if operand is not None and instruction.mnemonic in ("la", "lay"):
                destination = operand[0]
                address = _effective_address(operand, values)
                external_values.pop(destination, None)
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
                external = external_relocations.get(address) if address is not None else None
                if relocation and relocation["target_address"] is not None:
                    values[destination] = (relocation["target_address"], f"rld:{address:#x}", "high")
                    external_values.pop(destination, None)
                else:
                    values.pop(destination, None)
                    if external is not None:
                        external_values[destination] = (address, external)
                    else:
                        external_values.pop(destination, None)
                continue
            if instruction.mnemonic in ("lm", "lmg"):
                for register in range(instruction.data[1] >> 4, (instruction.data[1] & 15) + 1):
                    values.pop(register, None)
                    external_values.pop(register, None)
                continue
            for register in range(16):
                if _writes_register(instruction, register):
                    values.pop(register, None)
                    external_values.pop(register, None)
    edges.sort(key=lambda site: (site.caller_entry, site.site_rva, site.target_rva))
    unresolved.sort(key=lambda site: (site.caller_entry, site.site_rva))
    external_calls.sort(key=lambda site: (site.caller_entry, site.site_rva))
    links = _binder_links(edges, external_calls, decks)
    return CallGraph(nodes, edges, unresolved, external_calls, links)
