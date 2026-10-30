import argparse
import json

from .errors import TimiError
from .savf import read_savf, read_qzrdpack_header


def _print(value):
    print(json.dumps(value, indent=2))


def _savf_info(args):
    save = read_savf(args.input, args.maximum)
    result = save.to_dict()
    if args.summary:
        result = {key: value for key, value in result.items() if key != "items"}
        result["objects"] = [
            {"index": item.index, "name": item.name, "object_type": f"0x{item.object_type:04x}", "object_type_name": item.type_name}
            for item in save.items
        ]
    _print(result)
    return 0


def _savf_extract(args):
    save = read_savf(args.input, args.maximum)
    output = save.extract(args.output)
    _print({"output": str(output), "item_count": len(save.items), "record_count": save.record_count})
    return 0


def _qzrdpack_info(args):
    _print(read_qzrdpack_header(args.input))
    return 0


def build_parser():
    parser = argparse.ArgumentParser(prog="python3 -m ablation.ibm_timi", description="Dependency-free IBM i TIMI and SAVF analysis")
    subparsers = parser.add_subparsers(dest="command", required=True)
    commands = (
        ("savf-info", _savf_info, "input"),
        ("savf-extract", _savf_extract, "input output"),
        ("qzrd-info", _qzrdpack_info, "input"),
    )
    for name, handler, arguments in commands:
        sub = subparsers.add_parser(name)
        for argument in arguments.split():
            sub.add_argument(argument)
        sub.set_defaults(handler=handler)
        if name.startswith("savf-"):
            sub.add_argument("--maximum", type=int, default=512 * 1024 * 1024)
        if name == "savf-info":
            sub.add_argument("--summary", action="store_true")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except (TimiError, OSError, ValueError) as error:
        parser.exit(2, f"error: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
