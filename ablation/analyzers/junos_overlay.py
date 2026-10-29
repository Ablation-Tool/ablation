"""Recover conservative function-name overlays from Junos trace strings."""
from __future__ import annotations

import re
from dataclasses import dataclass

from ablation.analyzers.mips_string_xrefs import StringXref

_SYMBOL = re.compile(r"[A-Za-z_][A-Za-z0-9_]{3,79}\Z")


@dataclass(frozen=True)
class OverlayResult:
    names_added: int
    function_starts_added: int
    names: dict[int, str]


def candidate_name(value: str) -> str | None:
    if _SYMBOL.fullmatch(value) and "_" in value:
        return value
    return None


def recover_overlay(ctx, xrefs: list[StringXref]) -> OverlayResult:
    names: dict[int, str] = {}
    for xref in xrefs:
        if not xref.function_va or xref.function_va in names:
            continue
        value = ctx.strings.get(xref.string_va)
        if not value:
            continue
        name = candidate_name(value)
        if name is not None:
            names[xref.function_va] = name
    before = set(ctx.func_starts)
    ctx.func_starts = sorted(before | names.keys())
    added = ctx.set_names_bulk({va: (name, "junos_trace") for va, name in names.items()})
    return OverlayResult(added, len(names) - len(before & names.keys()), names)
