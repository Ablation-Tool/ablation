import argparse
import bisect
import json

from ablation.analyzers.insn_m88k import M88kDecoder
from ablation.core.coff_m88k_parser import parse as parse_coff
from ablation.core.elf_m88k_parser import parse as parse_elf


def _read(path):
    with open(path, "rb") as stream:
        prefix = stream.read(4)
    if prefix == b"\x7fELF":
        return parse_elf(path)
    return parse_coff(path)


def _print(value):
    print(json.dumps(value, indent=2))


def _info(args):
    binary = _read(args.input)
    _print({
        "path": binary.path, "entry": binary.entry,
        "text_start": binary.text_start, "data_start": binary.data_start,
        "sections": [{"name": item.name, "va": item.vaddr, "size": item.size, "flags": item.flags} for item in binary.sections],
        "needed": binary.needed,
        "plt": {hex(address): name for address, name in sorted(binary.plt.items())},
    })
    return 0


def _disassemble(args):
    binary = _read(args.input)
    decoder = M88kDecoder(binary)
    start = int(args.start, 0)
    instructions = list(decoder.disassemble_va(start, args.maximum))
    if args.json:
        _print([{
            "address": item.address, "raw": item.raw, "mnemonic": item.mnemonic,
            "operands": item.op_str, "known": item.known,
            "branch_target": item.branch_target, "is_call": item.is_call,
            "is_return": item.is_return,
        } for item in instructions])
    else:
        for item in instructions:
            print(item)
    return 0


def _calls(args):
    binary = _read(args.input)
    decoder = M88kDecoder(binary)
    starts = sorted(decoder.function_starts())
    rows = []
    text = binary.text
    va = text.vaddr
    while text.contains_va(va):
        item = decoder.decode_word(text.read_word(va), va)
        if item.is_call:
            owner = starts[bisect.bisect_right(starts, va) - 1] if starts and starts[0] <= va else None
            rows.append({
                "call_va": va, "target_va": item.branch_target,
                "name": binary.plt.get(item.branch_target), "owner_start": owner,
                "instruction": str(item),
            })
        va += 4
    if args.json:
        _print(rows)
    else:
        for row in rows:
            target = f"{row['target_va']:#x}" if row["target_va"] is not None else "indirect"
            owner = f"{row['owner_start']:#x}" if row["owner_start"] is not None else "unknown"
            print(f"{row['call_va']:#010x} -> {target:10s} {row['name'] or '<unresolved>':24s} owner={owner}")
    return 0


def _functions(args):
    binary = _read(args.input)
    starts = sorted(M88kDecoder(binary).function_starts())
    if args.json:
        _print(starts)
    else:
        for start in starts:
            print(f"{start:#010x}")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(prog="python3 -m ablation.m88k", description="Dependency-free MC88100 COFF and ELF analysis")
    subparsers = parser.add_subparsers(dest="command", required=True)
    info = subparsers.add_parser("info")
    info.add_argument("input")
    info.set_defaults(handler=_info)
    disassemble = subparsers.add_parser("disassemble")
    disassemble.add_argument("input")
    disassemble.add_argument("start")
    disassemble.add_argument("--maximum", type=int, default=512)
    disassemble.add_argument("--json", action="store_true")
    disassemble.set_defaults(handler=_disassemble)
    calls = subparsers.add_parser("calls")
    calls.add_argument("input")
    calls.add_argument("--json", action="store_true")
    calls.set_defaults(handler=_calls)
    functions = subparsers.add_parser("functions")
    functions.add_argument("input")
    functions.add_argument("--json", action="store_true")
    functions.set_defaults(handler=_functions)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except (OSError, ValueError, KeyError, IndexError) as error:
        parser.exit(2, f"error: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
