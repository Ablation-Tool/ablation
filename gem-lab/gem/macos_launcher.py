import sys

from .launcher import prepare_agent_path


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments == ["--self-test"]:
        import pyte
        assert pyte is not None
        print("GEM_MACOS_APP_OK", flush=True)
        return 0
    from .cli import main as cli_main
    if arguments:
        return cli_main(arguments)
    prepare_agent_path()
    return cli_main(["launch"])


if __name__ == "__main__":
    raise SystemExit(main())
