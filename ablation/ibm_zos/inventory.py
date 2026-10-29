from collections import Counter

from .functions import recover_functions


def _unknown_key(raw):
    return (raw[0], raw[1] if len(raw) > 1 else None, raw[-1] if raw[0] in (0xE3, 0xEB, 0xED) else None, len(raw))


def instruction_inventory(image, maximum_per_function=20000):
    recovery = recover_functions(image, True, maximum_per_function)
    mnemonics = Counter()
    formats = Counter()
    unknown = Counter()
    examples = {}
    instruction_count = 0
    known_count = 0
    incomplete_count = 0
    for function in recovery.functions:
        incomplete_count += function.complete is False
        for instruction in function.instructions:
            instruction_count += 1
            if instruction.known:
                known_count += 1
                mnemonics[instruction.mnemonic] += 1
                formats[instruction.format] += 1
                continue
            raw = instruction.data
            key = _unknown_key(raw)
            unknown[key] += 1
            examples.setdefault(key, raw.hex())
    unknown_records = [
        {
            "first_byte": key[0],
            "second_byte": key[1],
            "last_byte": key[2],
            "length": key[3],
            "count": count,
            "example_hex": examples[key],
        }
        for key, count in unknown.most_common()
    ]
    return {
        "source": image.source_name,
        "sha256": image.source_sha256,
        "function_count": len(recovery.functions),
        "incomplete_function_count": incomplete_count,
        "instruction_count": instruction_count,
        "known_instruction_count": known_count,
        "unknown_instruction_count": instruction_count - known_count,
        "mnemonic_counts": dict(mnemonics.most_common()),
        "format_counts": dict(formats.most_common()),
        "unknown_opcodes": unknown_records,
    }
