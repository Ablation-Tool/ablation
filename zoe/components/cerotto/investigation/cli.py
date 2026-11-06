"""Command-line entry point for CEROTTO investigations."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from .adapter import AdapterError, CerottoAdapter
from .engine import InvestigationEngine, InvestigationError


def parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    result = argparse.ArgumentParser(prog="cerotto-investigate")
    sub = result.add_subparsers(dest="command", required=True)
    investigate = sub.add_parser("investigate")
    investigate.add_argument("--db", required=True)
    investigate.add_argument("--case", required=True)
    investigate.add_argument("--conversation", required=True)
    investigate.add_argument("--host", default="")
    investigate.add_argument("--from", dest="from_", default="")
    investigate.add_argument("--to", default="")
    investigate.add_argument("--limit", type=int, default=200)
    investigate.add_argument("--binary", default=str(root / "build" / "cerotto")
                             if (root / "build" / "cerotto").exists()
                             else str(root.parent / "build" / "cerotto"))
    investigate.add_argument("--max-steps", type=int, default=8)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command != "investigate":
        raise SystemExit(2)
    try:
        from .transport import LLMTransport
        adapter = CerottoAdapter(
            args.binary, args.db, args.case, args.conversation,
            scope_host=args.host, scope_from=args.from_, scope_to=args.to,
            default_limit=args.limit,
        )
        transport = LLMTransport(
            model=os.environ.get("CEROTTO_MODEL"),
            api_key=os.environ.get("CEROTTO_API_KEY"),
        )
        engine = InvestigationEngine(adapter, transport, max_steps=args.max_steps)
        result = engine.run()
        print(json.dumps(result.to_dict(), indent=2))
        return 0 if result.finished else 2
    except (AdapterError, InvestigationError, RuntimeError, ValueError) as exc:
        print(f"investigation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
