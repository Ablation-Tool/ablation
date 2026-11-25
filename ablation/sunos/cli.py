from __future__ import annotations

import argparse
import json

from ablation.analyzers.sunos_aout import AoutError, read_aout, render_calls, render_dispatch


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="python -m ablation.sunos")
    commands = result.add_subparsers(dest="command", required=True)
    for name in ("info", "calls", "render", "dispatch"):
        command = commands.add_parser(name)
        command.add_argument("input")
        if name != "info":
            command.add_argument("--target", type=lambda value: int(value, 0), required=name == "dispatch")
        if name == "dispatch":
            command.add_argument("--register", default="%o1")
            command.add_argument("--wrapper", type=lambda value: int(value, 0), action="append", default=[])
        command.add_argument("--json", action="store_true")
    return result


def main(argv=None) -> int:
    arguments = parser().parse_args(argv)
    try:
        image = read_aout(arguments.input)
        if arguments.command == "info":
            document = image.to_dict()
            print(json.dumps(document, indent=2) if arguments.json else
                  f"{document['format']}\nsha256={document['sha256']}\nsymbols={document['symbol_count']} relocations={document['relocation_count']}")
            return 0
        if arguments.command == "dispatch":
            if arguments.json:
                arguments_list = image.dispatch_arguments(arguments.target, arguments.register, tuple(arguments.wrapper))
                print(json.dumps([item.to_dict() for item in arguments_list], indent=2))
            else:
                print(render_dispatch(image, arguments.target, arguments.register, tuple(arguments.wrapper)), end="")
        elif arguments.command == "calls" and arguments.json:
            print(json.dumps([item.to_dict() for item in image.calls(arguments.target)], indent=2))
        else:
            print(render_calls(image, arguments.target), end="")
        return 0
    except (OSError, AoutError, ValueError) as error:
        raise SystemExit(f"ablation.sunos: {error}")


if __name__ == "__main__":
    raise SystemExit(main())
