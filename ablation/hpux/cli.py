import argparse
import json

from .som import SomError, read_som


def _print(value):
    print(json.dumps(value, indent=2))


def _info(args):
    image = read_som(args.input)
    _print(image.to_dict(full=args.full))
    return 0


def _imports(args):
    image = read_som(args.input)
    dlt_count = len(image.dlt)
    rows = []
    for item in image.imports:
        if args.external_code and not (item.type == 3 and item.external):
            continue
        row = dict(item.__dict__)
        row["type_name"] = item.type_name
        if item.index < dlt_count:
            row["linkage"] = {"kind": "DLT", "index": item.index, "value": image.dlt[item.index].value}
        else:
            entry = image.plt[item.index - dlt_count]
            row["linkage"] = {"kind": "PLT", "index": entry.index, "va": entry.va, "proc_addr": entry.proc_addr}
        rows.append(row)
    if args.json:
        _print(rows)
    else:
        for row in rows:
            link = row["linkage"]
            detail = f"DLT {link['index']}={link['value']:#x}" if link["kind"] == "DLT" else f"PLT {link['index']} {link['va']:#x} -> {link['proc_addr']:#x}"
            print(f"{row['index']:5d} {row['name'] or '<null>':40s} {row['type_name']:10s} {detail}")
    return 0


def _disassemble(args):
    image = read_som(args.input)
    start = int(args.start, 0)
    end = start + int(args.length, 0)
    instructions = list(image.instructions(start, end, args.maximum))
    if args.json:
        _print([{
            "address": item.address, "word": item.word, "mnemonic": item.mnemonic,
            "operands": item.operands, "arch": item.arch, "known": item.known,
            "branch_target": item.branch_target, "is_call": item.is_call,
            "is_return": item.is_return,
        } for item in instructions])
    else:
        for item in instructions:
            print(item.text())
    return 0


def _calls(args):
    image = read_som(args.input)
    start = int(args.start, 0)
    end = start + int(args.length, 0)
    calls = list(image.call_sites(start, end, args.maximum))
    if args.json:
        _print(calls)
    else:
        for call in calls:
            target = f"{call['target_va']:#x}" if call["target_va"] is not None else "indirect"
            name = call["name"] or "<unresolved>"
            owner = f"{call['owner_start']:#x}" if call["owner_start"] is not None else "unknown"
            print(f"{call['call_va']:#010x} -> {target:10s} {name:40s} owner={owner}")
    return 0


def _functions(args):
    image = read_som(args.input)
    rows = [item.__dict__ for item in image.unwind]
    if args.json:
        _print(rows)
    else:
        for item in image.unwind:
            export = next((export.name for export in image.exports if export.value == item.start and export.type == 3), None)
            suffix = f" {export}" if export else ""
            print(f"{item.start:#010x}..{item.end:#010x} frame={item.frame_info:#x}{suffix}")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(prog="python3 -m ablation.hpux", description="Dependency-free HP-UX SOM and PA-RISC analysis")
    subparsers = parser.add_subparsers(dest="command", required=True)
    info = subparsers.add_parser("info")
    info.add_argument("input")
    info.add_argument("--full", action="store_true")
    info.set_defaults(handler=_info)
    imports = subparsers.add_parser("imports")
    imports.add_argument("input")
    imports.add_argument("--external-code", action="store_true")
    imports.add_argument("--json", action="store_true")
    imports.set_defaults(handler=_imports)
    disassemble = subparsers.add_parser("disassemble")
    disassemble.add_argument("input")
    disassemble.add_argument("start")
    disassemble.add_argument("--length", default="0x80")
    disassemble.add_argument("--maximum", type=int, default=100000)
    disassemble.add_argument("--json", action="store_true")
    disassemble.set_defaults(handler=_disassemble)
    calls = subparsers.add_parser("calls")
    calls.add_argument("input")
    calls.add_argument("start")
    calls.add_argument("--length", default="0x80")
    calls.add_argument("--maximum", type=int, default=100000)
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
    except (SomError, OSError, ValueError) as error:
        parser.exit(2, f"error: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
