"""SunOS SPARC a.out analysis."""

from ablation.analyzers.sunos_aout import (
    AoutError,
    AoutHeader,
    AoutSymbol,
    AoutRelocation,
    AoutCall,
    AoutCallArgument,
    SunosAout,
    parse_aout,
    read_aout,
    render_calls,
    render_dispatch,
)

__all__ = [
    "AoutError", "AoutHeader", "AoutSymbol", "AoutRelocation", "AoutCall",
    "AoutCallArgument", "SunosAout", "parse_aout", "read_aout", "render_calls",
    "render_dispatch",
]
