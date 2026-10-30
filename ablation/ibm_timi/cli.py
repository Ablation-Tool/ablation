import argparse
import json

from .catalogue import parse_legacy_catalogue
from .errors import FormatError, TimiError, UnsupportedFormatError
from .program import read_program_bytes, recover_program, recover_program_file
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


def _catalogue_info(args):
    save = read_savf(args.input, args.maximum)
    item = next((item for item in save.items if item.object_type == 0x19DB), None)
    if item is None:
        raise FormatError("SAVF has no legacy catalogue item")
    _print(parse_legacy_catalogue(item, f"{args.input}:{item.name}").to_dict())
    return 0


def _program_info(args):
    _print(recover_program_file(args.input).to_dict())
    return 0


def _program_extract(args):
    data = read_program_bytes(args.input)
    recovery = recover_program(data, str(args.input))
    output = recovery.extract(data, args.output)
    _print({"output": str(output), "code_start": recovery.code_start, "code_end_inclusive": recovery.code_end})
    return 0


def _opm_decode(args):
    data = read_program_bytes(args.input)
    recovery = recover_program(data, str(args.input))
    if not hasattr(recovery, "decode_at"):
        raise UnsupportedFormatError("OPM instruction decoding requires an OPM program")
    _print(recovery.decode_at(data, int(args.offset, 0)))
    return 0


def build_parser():
    parser = argparse.ArgumentParser(prog="python3 -m ablation.ibm_timi", description="Dependency-free IBM i TIMI and SAVF analysis")
    subparsers = parser.add_subparsers(dest="command", required=True)
    commands = (
        ("savf-info", _savf_info, "input"),
        ("savf-extract", _savf_extract, "input output"),
        ("qzrd-info", _qzrdpack_info, "input"),
        ("catalogue-info", _catalogue_info, "input"),
        ("program-info", _program_info, "input"),
        ("program-extract", _program_extract, "input output"),
        ("opm-decode", _opm_decode, "input offset"),
    )
    for name, handler, arguments in commands:
        sub = subparsers.add_parser(name)
        for argument in arguments.split():
            sub.add_argument(argument)
        sub.set_defaults(handler=handler)
        if name in ("savf-info", "savf-extract", "catalogue-info"):
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
