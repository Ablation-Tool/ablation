import hashlib
import re

from .functions import decode_cfg, recover_functions
from .sid import compare_inventories, demangle_ibm_cpp, normalize_name


def _function_key(function):
    normalized = normalize_name(function.name)
    if normalized:
        return ("name", normalized)
    return ("prolog", function.kind)


def _instructions(function, decoder):
    if function.instructions:
        return function.instructions
    instructions, _, _, _ = decoder(function.code_rva)
    return instructions


def _normalized_instruction(instruction):
    if not instruction.known:
        return f"unknown:{instruction.data.hex()}"
    operands = instruction.operands
    if instruction.target is not None:
        operands = re.sub(r"0x[0-9a-f]+", "<target>", operands)
    operands = re.sub(r"(?<![%\w])0x[0-9a-f]+", "<imm>", operands)
    return f"{instruction.mnemonic}:{operands}"


def _hash_functions(image, recovery, decoder):
    result = {}
    for function in recovery.functions:
        instructions = _instructions(function, decoder)
        normalized = "\n".join(_normalized_instruction(instruction) for instruction in instructions)
        digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        key = _function_key(function)
        result.setdefault(key, []).append({
            "entry_rva": function.entry_rva,
            "code_rva": function.code_rva,
            "kind": function.kind,
            "hash": digest,
            "instruction_count": len(instructions),
            "unknown_instruction_count": sum(not item.known for item in instructions),
        })
    return result


def _match_entries(left_entries, right_entries):
    left_hashes = {entry["hash"]: entry for entry in left_entries}
    right_hashes = {entry["hash"]: entry for entry in right_entries}
    common = left_hashes.keys() & right_hashes.keys()
    matches = []
    for digest in sorted(common):
        left = left_hashes[digest]
        right = right_hashes[digest]
        matches.append({
            "left_entry_rva": left["entry_rva"],
            "right_entry_rva": right["entry_rva"],
            "hash": digest,
            "instruction_count_left": left["instruction_count"],
            "instruction_count_right": right["instruction_count"],
        })
    return matches


def _semantic_side_deck_comparison(left, right):
    def inventory(deck):
        result = {}
        for statement in deck.statements:
            demangled, status = demangle_ibm_cpp(statement.symbol)
            name = statement.demangled or demangled
            normalized = normalize_name(name)
            if normalized:
                result.setdefault(normalized, statement.symbol)
        return result

    left_symbols = inventory(left)
    right_symbols = inventory(right)
    intersection = left_symbols.keys() & right_symbols.keys()
    union = left_symbols.keys() | right_symbols.keys()
    return {
        "left_count": len(left_symbols),
        "right_count": len(right_symbols),
        "intersection_count": len(intersection),
        "left_only_count": len(left_symbols.keys() - right_symbols.keys()),
        "right_only_count": len(right_symbols.keys() - left_symbols.keys()),
        "jaccard": len(intersection) / len(union) if union else 1.0,
    }


def compare_images(left, right, maximum_per_function=20000):
    left_recovery = recover_functions(left)
    right_recovery = recover_functions(right)
    from .s390 import S390Decoder

    decoder = S390Decoder()
    left_functions = _hash_functions(
        left, left_recovery,
        lambda start: decode_cfg(left.text, start, decoder, maximum_per_function),
    )
    right_functions = _hash_functions(
        right, right_recovery,
        lambda start: decode_cfg(right.text, start, decoder, maximum_per_function),
    )
    keys = left_functions.keys() | right_functions.keys()
    exact_matches = []
    left_only = []
    right_only = []
    changed = []
    for key in sorted(keys):
        if key not in left_functions:
            right_only.extend(right_functions[key])
            continue
        if key not in right_functions:
            left_only.extend(left_functions[key])
            continue
        matches = _match_entries(left_functions[key], right_functions[key])
        exact_matches.extend({"key": key[1], "match_type": key[0], **match} for match in matches)
        matched_left = {match["left_entry_rva"] for match in matches}
        matched_right = {match["right_entry_rva"] for match in matches}
        for entry in left_functions[key]:
            if entry["entry_rva"] not in matched_left:
                changed.append({"side": "left", "key": key[1], **entry})
        for entry in right_functions[key]:
            if entry["entry_rva"] not in matched_right:
                changed.append({"side": "right", "key": key[1], **entry})
    return {
        "left": left.source_name,
        "right": right.source_name,
        "left_sha256": left.source_sha256,
        "right_sha256": right.source_sha256,
        "text_identical": left.text == right.text,
        "left_function_count": len(left_recovery.functions),
        "right_function_count": len(right_recovery.functions),
        "exact_function_match_count": len(exact_matches),
        "left_unmatched_function_count": sum(item["side"] == "left" for item in changed) + len(left_only),
        "right_unmatched_function_count": sum(item["side"] == "right" for item in changed) + len(right_only),
        "exact_matches": exact_matches,
        "left_only_functions": left_only,
        "right_only_functions": right_only,
        "changed_functions": changed,
    }


def compare_side_decks(left, right):
    return {
        "left": left.source_name,
        "right": right.source_name,
        "raw": compare_inventories(left, right),
        "semantic": _semantic_side_deck_comparison(left, right),
    }
