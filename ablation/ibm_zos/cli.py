import argparse
import json
from pathlib import Path

from .callgraph import build_call_graph
from .compare import compare_images, compare_side_decks
from .decompiler import S390Decompiler
from .errors import IbmZosError
from .functions import recover_functions
from .inventory import instruction_inventory
from .io_utils import ensure_directory, write_bytes, write_text
from .loadmodule import parse_load_image, read_load_image
from .netdata import extract_dataset, read_netdata
from .relocation import relocate_image
from .s390 import S390Decoder
from .sid import correlate_functions, read_side_deck


def _print(value):
    print(json.dumps(value, indent=2))


def _netdata_list(args):
    netdata = read_netdata(args.input)
    _print(netdata.to_dict())
    return 0


def _netdata_extract(args):
    netdata = read_netdata(args.input)
    output = ensure_directory(args.output)
    names = [args.dataset] if args.dataset else list(netdata.datasets)
    roots = [str(extract_dataset(netdata, name, output, args.overwrite)) for name in names]
    for index, message in enumerate(netdata.messages, 1):
        path = output / f"message-{index}.bin"
        write_bytes(path, message, args.overwrite)
    write_text(output / "netdata.json", json.dumps(netdata.to_dict(), indent=2) + "\n", args.overwrite)
    _print({"datasets": roots, "message_count": len(netdata.messages)})
    return 0


def _image_info(args):
    image = read_load_image(args.input)
    if args.output:
        image.write(args.output)
    _print(image.to_dict())
    return 0


def _disassemble(args):
    image = read_load_image(args.input)
    start = int(args.start, 0)
    end = start + int(args.length, 0)
    if start < 0 or end > len(image.text) or start >= end:
        raise ValueError("disassembly range outside load image")
    instructions = list(S390Decoder().linear(image.text, start, end, args.maximum))
    if args.json:
        _print([item.to_dict() for item in instructions])
    else:
        for instruction in instructions:
            print(instruction.text())
    return 0


def _functions(args):
    image = read_load_image(args.input)
    recovery = recover_functions(image, args.cfg, args.maximum)
    recovery.write(args.output, args.cfg)
    _print({key: value for key, value in recovery.to_dict().items() if key not in ("anchors", "functions")})
    return 0


def _sid(args):
    deck = read_side_deck(args.input)
    deck.write(args.output)
    _print(deck.to_dict(include_statements=False))
    return 0


def _correlate(args):
    image = read_load_image(args.input)
    recovery = recover_functions(image)
    decks = [read_side_deck(path) for path in args.sid]
    result = correlate_functions(recovery, decks)
    write_text(args.output, json.dumps(result, indent=2) + "\n")
    _print({"match_count": result["match_count"], "output": args.output})
    return 0


def _pipeline(args):
    netdata = read_netdata(args.input)
    output = ensure_directory(args.output)
    results = []
    for dataset in netdata.datasets.values():
        root = extract_dataset(netdata, dataset.name, output, args.overwrite)
        for member in dataset.members.values():
            if member.is_alias:
                continue
            raw_path = root / f"{member.name}{member.suffix}"
            item = {"dataset": dataset.name, "member": member.name, "raw": str(raw_path)}
            try:
                image = parse_load_image(member.data, f"{dataset.name}({member.name})")
            except IbmZosError:
                item.update({"kind": "uninterpreted"})
                if dataset.record_format.startswith("F") and dataset.logical_record_length == 80:
                    try:
                        deck = read_side_deck(raw_path)
                    except IbmZosError:
                        pass
                    else:
                        deck.write(root / member.name)
                        item.update({"kind": "side_deck", "imports": len(deck.statements)})
            else:
                item.update({"kind": "load_image", "format": image.format, "text_size": len(image.text)})
                if args.deep:
                    image.write(root / member.name)
                    recovery = recover_functions(image, args.cfg, args.maximum)
                    recovery.write(root / f"{member.name}-functions", args.cfg)
                    item["function_count"] = len(recovery.functions)
                    if args.cfg:
                        graph = build_call_graph(image, recovery)
                        graph.write(root / f"{member.name}-callgraph")
                        item["callgraph_edges"] = len(graph.edges)
            results.append(item)
    summary = {"source": args.input, "items": results}
    write_text(output / "pipeline.json", json.dumps(summary, indent=2) + "\n", args.overwrite)
    _print(summary)
    return 0


def _relocate(args):
    image = read_load_image(args.input)
    relocated, report = relocate_image(image, int(args.base, 0))
    output = ensure_directory(args.output)
    write_bytes(output / "relocated-text.bin", relocated)
    write_text(output / "relocations.json", json.dumps(report, indent=2) + "\n")
    _print({key: value for key, value in report.items() if key != "entries"})
    return 0


def _callgraph(args):
    image = read_load_image(args.input)
    recovery = recover_functions(image, True, args.maximum)
    graph = build_call_graph(image, recovery)
    graph.write(args.output)
    result = graph.to_dict()
    _print({key: value for key, value in result.items() if key not in ("nodes", "edges", "unresolved_calls")})
    return 0


def _decompile(args):
    image = read_load_image(args.input)
    recovery = recover_functions(image, True, args.maximum)
    graph = build_call_graph(image, recovery)
    decompiler = S390Decompiler(image, recovery, graph)
    output = ensure_directory(args.output)
    functions = recovery.functions
    if args.function is not None:
        address = int(args.function, 0)
        functions = [function for function in functions if address in (function.entry_rva, function.code_rva)]
        if not functions:
            raise ValueError(f"no function at {address:#x}")
    results = [decompiler.write(function, output) for function in functions]
    summary = {
        "function_count": len(results),
        "structured_loop_count": sum(result.structured_loop_count for result in results),
        "unknown_statement_count": sum(result.unknown_statement_count for result in results),
        "functions": [{key: value for key, value in result.to_dict().items() if key != "pseudo_c"} for result in results],
    }
    write_text(output / "decompilation.json", json.dumps(summary, indent=2) + "\n")
    _print({key: value for key, value in summary.items() if key != "functions"})
    return 0


def _compare(args):
    result = compare_images(read_load_image(args.left), read_load_image(args.right), args.maximum)
    write_text(args.output, json.dumps(result, indent=2) + "\n")
    _print({key: value for key, value in result.items() if not isinstance(value, list)})
    return 0


def _sid_compare(args):
    result = compare_side_decks(read_side_deck(args.left), read_side_deck(args.right))
    write_text(args.output, json.dumps(result, indent=2) + "\n")
    _print(result)
    return 0


def _opcode_inventory(args):
    result = instruction_inventory(read_load_image(args.input), args.maximum)
    write_text(args.output, json.dumps(result, indent=2) + "\n")
    _print({key: value for key, value in result.items() if key not in ("mnemonic_counts", "format_counts", "unknown_opcodes")})
    return 0


def build_parser():
    parser = argparse.ArgumentParser(prog="python3 -m ablation.ibm_zos", description="Dependency-free z/OS artifact analysis")
    subparsers = parser.add_subparsers(dest="command", required=True)
    commands = (
        ("netdata-list", _netdata_list, "input"),
        ("netdata-extract", _netdata_extract, "input output"),
        ("image-info", _image_info, "input"),
        ("disasm", _disassemble, "input"),
        ("functions", _functions, "input output"),
        ("sid", _sid, "input output"),
        ("correlate", _correlate, "input output sid"),
        ("pipeline", _pipeline, "input output"),
        ("relocate", _relocate, "input output"),
        ("callgraph", _callgraph, "input output"),
        ("decompile", _decompile, "input output"),
        ("compare", _compare, "left right output"),
        ("sid-compare", _sid_compare, "left right output"),
        ("opcode-inventory", _opcode_inventory, "input output"),
    )
    for name, handler, arguments in commands:
        sub = subparsers.add_parser(name)
        for argument in arguments.split():
            if argument == "sid":
                sub.add_argument("sid", nargs="+")
            else:
                sub.add_argument(argument)
        sub.set_defaults(handler=handler)
    for name in ("netdata-extract", "pipeline"):
        sub = subparsers.choices[name]
        sub.add_argument("--overwrite", action="store_true")
    subparsers.choices["netdata-extract"].add_argument("--dataset")
    subparsers.choices["image-info"].add_argument("--output")
    disasm = subparsers.choices["disasm"]
    disasm.add_argument("--start", default="0")
    disasm.add_argument("--length", default="256")
    disasm.add_argument("--maximum", type=int, default=1000)
    disasm.add_argument("--json", action="store_true")
    for name in ("functions", "pipeline"):
        sub = subparsers.choices[name]
        sub.add_argument("--cfg", action="store_true")
        sub.add_argument("--maximum", type=int, default=20000)
    for name in ("callgraph", "decompile", "compare", "opcode-inventory"):
        subparsers.choices[name].add_argument("--maximum", type=int, default=20000)
    subparsers.choices["relocate"].add_argument("--base", default="0")
    subparsers.choices["decompile"].add_argument("--function")
    subparsers.choices["pipeline"].add_argument("--deep", action="store_true")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except (IbmZosError, OSError, ValueError, KeyError) as error:
        parser.exit(2, f"error: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
