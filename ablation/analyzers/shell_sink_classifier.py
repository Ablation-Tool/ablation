"""
shell_sink_classifier.py: classify exec-class sink provenance in POSIX shell scripts.

Why this exists:
1. IoT and embedded Linux firmware uses shell CGI handlers as the primary web attack
   surface. VIVOTEK, Dahua, Hikvision, and most IP camera vendors ship 50-100 shell
   scripts as CGI handlers. Without this tool, classifying all exec sinks requires
   reading every line manually (2+ hours for a 2500-line handler like upload_vadp).

2. SinkArgClassifier classifies exec sinks in ELF binaries. There was no equivalent
   for shell scripts — a direct gap when the attack surface is shell.

3. Existing source_taint_tracker.py targets Python source. PerlTaintScanner targets
   Perl. Neither handles POSIX sh/bash syntax.

Verdict classes (aligned with SinkArgClassifier):
  RODATA_CONST      — all command tokens are literal strings; no injection possible
  ARG_PROPAGATED    — command contains a variable with confirmed external provenance
                      (positional params, CGI env, XML/config tool output, stdin)
  UNKNOWN           — command contains a variable whose origin is not visible in-file
  EVAL_SINK         — eval with any provenance; always requires manual review

Exec-class sinks detected:
  1. Variable in command position: ``${VAR}/script`` or ``$VAR args``
  2. ``eval EXPR``
  3. ``source $VAR`` / ``. $VAR``
  4. ``sh -c CMD`` / ``bash -c CMD`` / ``/bin/sh -c CMD``
  5. Unquoted ``$VAR`` or ``${VAR}`` as a direct command (not an argument)

External-provenance sources (ARG_PROPAGATED triggers):
  - Positional: $1 $2 … $9 ${1} ${2} $@ $*
  - CGI env:    $QUERY_STRING $PATH_INFO $CONTENT_TYPE $HTTP_* $CGI_* $SCRIPT_NAME
  - Tool output: $(xmlparser ...) $(confclient ...) $(stormgr ...) $(getcgi ...)
                 $(cat ...) on attacker-reachable paths
  - Stdin:      ``read VAR`` assignments
  - Any $(cmd) subshell assigned to a variable when cmd is in the EXTERNAL_CMDS set

Usage::

    from ablation.analyzers.shell_sink_classifier import ShellSinkClassifier

    clf = ShellSinkClassifier.from_path('/usr/bin/upload_vadp')
    results = clf.classify()
    print(clf.report(results))

    # Filter to non-safe findings:
    flagged = [r for r in results if r.verdict != 'RODATA_CONST']

    # Scan a CGI directory:
    clf = ShellSinkClassifier.from_dir('/usr/share/www/cgi-bin/', exts={'.cgi', '.sh', ''})
    results = clf.classify()

CLI::

    python3 -m ablation.analyzers.shell_sink_classifier /path/to/script.sh
    python3 -m ablation.analyzers.shell_sink_classifier /path/to/cgi-bin/
    python3 -m ablation.analyzers.shell_sink_classifier /path/to/script.sh --flagged-only
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# External input sources — command substitutions that return attacker data
# ---------------------------------------------------------------------------

# Tool names whose output is treated as external/attacker-influenced input
_EXTERNAL_CMDS: Set[str] = {
    'xmlparser', 'xml_parser', 'confclient', 'stormgr', 'getcgi',
    'getparam', 'cgiget', 'cgi_get', 'read_param', 'getenv',
    'awk', 'sed', 'cut', 'tr',         # transform of potentially external data
    'decode.sh', 'urldecode', 'base64',
}

# CGI/HTTP environment variable names (prefix-matched)
_EXTERNAL_ENV_PREFIXES = (
    'QUERY_STRING', 'PATH_INFO', 'PATH_TRANSLATED', 'CONTENT_TYPE',
    'CONTENT_LENGTH', 'HTTP_', 'CGI_', 'REQUEST_METHOD', 'SCRIPT_NAME',
    'SERVER_', 'REMOTE_', 'AUTH_TYPE',
)

# Positional parameter pattern: $1 $2 ... $9 ${1} ... $@ $*
_RE_POSITIONAL = re.compile(r'\$(?:[1-9@*]|\{[1-9]\}|\{@\}|\{\*\})')

# Variable reference in a value: $VAR or ${VAR}
_RE_VAR_REF = re.compile(r'\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?')

# Assignment: VAR=... or VAR="..." or local VAR=... or export VAR=...
_RE_ASSIGN = re.compile(
    r'^(?:local\s+|export\s+|readonly\s+)?'
    r'([A-Za-z_][A-Za-z0-9_]*)='
    r'(.*)',
    re.MULTILINE,
)

# Command substitution: $(cmd ...) or `cmd ...`
_RE_CMD_SUBST_DOLLAR = re.compile(r'\$\(([^)]+)\)')
_RE_CMD_SUBST_BACKTICK = re.compile(r'`([^`]+)`')

# eval sink
_RE_EVAL = re.compile(r'^\s*eval\s+(.*)', re.MULTILINE)

# source / dot sink
_RE_SOURCE = re.compile(r'^\s*(?:source|\.)\s+(\S+)', re.MULTILINE)

# sh/bash -c sink
_RE_SH_C = re.compile(
    r'^\s*(?:/bin/sh|/bin/bash|sh|bash)\s+(?:-[a-zA-Z]*\s+)*-c\s+(.*)',
    re.MULTILINE,
)

# Variable-as-command: line starting with $VAR or ${VAR} (possibly with path prefix)
# e.g.  ${NEW_PACK}/${NEW_INIT_SCR} args
#       $SCRIPT args
_RE_VAR_CMD = re.compile(
    r'^\s*'
    r'(?:[^$\s#][^$\s]*)?'            # optional literal prefix (e.g. /some/path/)
    r'(?:\$\{?[A-Za-z_][A-Za-z0-9_]*\}?/?)+'  # one or more var refs (possibly with /)
    r'(?:[^\s]*)?'                    # optional suffix
    r'\s',                            # followed by space (i.e. there are arguments)
)

# Stripped comment / blank line
_RE_BLANK_OR_COMMENT = re.compile(r'^\s*(?:#.*)?$')


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class VarRecord:
    name: str
    provenance: str          # "EXTERNAL" | "INTERNAL" | "UNKNOWN"
    assigned_line: int
    assigned_value: str


@dataclass
class ShellSinkResult:
    script_path: str
    line_num: int
    line: str
    sink_type: str           # "VAR_CMD" | "EVAL" | "SOURCE" | "SH_C"
    command_fragment: str    # the token being classified
    verdict: str             # "RODATA_CONST" | "ARG_PROPAGATED" | "UNKNOWN" | "EVAL_SINK"
    vars_involved: List[str] = field(default_factory=list)
    var_provenances: Dict[str, str] = field(default_factory=dict)  # name -> provenance

    def fmt(self) -> str:
        varinfo = ', '.join(
            f'{v}={self.var_provenances.get(v, "UNKNOWN")}'
            for v in self.vars_involved
        )
        return (
            f"[{self.verdict:<16}] {Path(self.script_path).name}:{self.line_num}"
            f"  sink={self.sink_type}  vars=[{varinfo}]\n"
            f"  >> {self.line.strip()}"
        )


# ---------------------------------------------------------------------------
# ShellSinkClassifier
# ---------------------------------------------------------------------------

class ShellSinkClassifier:
    """Classify exec-class sink argument provenance in POSIX shell scripts."""

    def __init__(self, scripts: List[Path]):
        self._scripts = scripts

    @classmethod
    def from_path(cls, path: str | Path) -> "ShellSinkClassifier":
        p = Path(path)
        if p.is_dir():
            return cls.from_dir(str(p))
        return cls([p])

    @classmethod
    def from_dir(
        cls,
        directory: str | Path,
        exts: Optional[Set[str]] = None,
        max_size: int = 512 * 1024,
    ) -> "ShellSinkClassifier":
        """Collect all shell scripts under *directory*."""
        if exts is None:
            exts = {'.sh', '.cgi', ''}
        scripts: List[Path] = []
        for p in Path(directory).rglob('*'):
            if not p.is_file():
                continue
            if p.suffix in exts or p.suffix == '':
                try:
                    if p.stat().st_size > max_size:
                        continue
                    with p.open('rb') as f:
                        hdr = f.read(64)
                    if b'#!/bin/sh' in hdr or b'#!/bin/bash' in hdr or b'#!/usr/bin/env sh' in hdr:
                        scripts.append(p)
                    elif p.suffix in ('.sh', '.cgi'):
                        scripts.append(p)
                except OSError:
                    pass
        return cls(scripts)

    # ------------------------------------------------------------------
    # Main API
    # ------------------------------------------------------------------

    def classify(self) -> List[ShellSinkResult]:
        results: List[ShellSinkResult] = []
        for script in self._scripts:
            try:
                text = script.read_text(errors='replace')
            except OSError:
                continue
            results.extend(self._classify_script(str(script), text))
        return results

    @staticmethod
    def report(results: List[ShellSinkResult]) -> str:
        if not results:
            return "ShellSinkClassifier: no exec-class sinks found.\n"
        lines = [
            f"ShellSinkClassifier: {len(results)} exec-class sink(s)\n",
            f"{'VERDICT':<18} {'FILE:LINE':<40} {'SINK':<10} VARS\n",
            "-" * 90 + "\n",
        ]
        verdict_order = ('ARG_PROPAGATED', 'UNKNOWN', 'EVAL_SINK', 'RODATA_CONST')
        sorted_results = sorted(
            results,
            key=lambda r: (verdict_order.index(r.verdict) if r.verdict in verdict_order else 99,
                           r.script_path, r.line_num),
        )
        for r in sorted_results:
            name = f"{Path(r.script_path).name}:{r.line_num}"
            varinfo = ', '.join(
                f'{v}={r.var_provenances.get(v, "?")}' for v in r.vars_involved
            ) or '(literal)'
            lines.append(f"{r.verdict:<18} {name:<40} {r.sink_type:<10} {varinfo}\n")
            lines.append(f"    {r.line.strip()}\n")
        counts = {v: sum(1 for r in results if r.verdict == v) for v in verdict_order}
        lines.append(
            f"\nSummary: ARG_PROPAGATED={counts['ARG_PROPAGATED']} "
            f"UNKNOWN={counts['UNKNOWN']} EVAL_SINK={counts['EVAL_SINK']} "
            f"RODATA_CONST={counts['RODATA_CONST']}\n"
        )
        return ''.join(lines)

    # ------------------------------------------------------------------
    # Per-script analysis
    # ------------------------------------------------------------------

    def _classify_script(self, path: str, text: str) -> List[ShellSinkResult]:
        # Strip continuation lines for easier parsing
        joined = re.sub(r'\\\n\s*', ' ', text)
        raw_lines = text.splitlines()
        joined_lines = joined.splitlines()

        # Pass 1: build variable provenance table
        var_table: Dict[str, VarRecord] = {}
        self._build_var_table(joined_lines, var_table)

        # Pass 2: find exec-class sinks
        results: List[ShellSinkResult] = []
        for lineno, line in enumerate(joined_lines, 1):
            stripped = line.strip()
            if _RE_BLANK_OR_COMMENT.match(stripped):
                continue

            # eval
            m = _RE_EVAL.match(stripped)
            if m:
                expr = m.group(1).strip()
                verdict, vars_inv, prov = self._classify_expr(expr, var_table)
                results.append(ShellSinkResult(
                    script_path=path, line_num=lineno,
                    line=raw_lines[lineno - 1] if lineno <= len(raw_lines) else line,
                    sink_type='EVAL', command_fragment=expr,
                    verdict='EVAL_SINK',     # eval always requires manual review
                    vars_involved=vars_inv, var_provenances=prov,
                ))
                continue

            # source / dot
            m = _RE_SOURCE.match(stripped)
            if m:
                arg = m.group(1)
                verdict, vars_inv, prov = self._classify_expr(arg, var_table)
                results.append(ShellSinkResult(
                    script_path=path, line_num=lineno,
                    line=raw_lines[lineno - 1] if lineno <= len(raw_lines) else line,
                    sink_type='SOURCE', command_fragment=arg,
                    verdict=verdict,
                    vars_involved=vars_inv, var_provenances=prov,
                ))
                continue

            # sh/bash -c
            m = _RE_SH_C.match(stripped)
            if m:
                arg = m.group(1).strip()
                verdict, vars_inv, prov = self._classify_expr(arg, var_table)
                results.append(ShellSinkResult(
                    script_path=path, line_num=lineno,
                    line=raw_lines[lineno - 1] if lineno <= len(raw_lines) else line,
                    sink_type='SH_C', command_fragment=arg,
                    verdict=verdict,
                    vars_involved=vars_inv, var_provenances=prov,
                ))
                continue

            # Variable-as-command (first token contains $VAR)
            # Only flag if the line starts a command (not an assignment)
            if not re.match(r'^\s*[A-Za-z_][A-Za-z0-9_]*=', stripped):
                cmd_token = stripped.split()[0] if stripped.split() else ''
                if _RE_VAR_REF.search(cmd_token):
                    verdict, vars_inv, prov = self._classify_expr(cmd_token, var_table)
                    if vars_inv:  # only report if variables are present
                        results.append(ShellSinkResult(
                            script_path=path, line_num=lineno,
                            line=raw_lines[lineno - 1] if lineno <= len(raw_lines) else line,
                            sink_type='VAR_CMD', command_fragment=cmd_token,
                            verdict=verdict,
                            vars_involved=vars_inv, var_provenances=prov,
                        ))

        return results

    def _build_var_table(
        self, lines: List[str], var_table: Dict[str, VarRecord]
    ) -> None:
        """First pass: record every variable assignment and its provenance."""
        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()
            if _RE_BLANK_OR_COMMENT.match(stripped):
                continue

            # read VAR — stdin input
            m = re.match(r'^\s*read\s+(-[a-zA-Z]+\s+)*([A-Za-z_][A-Za-z0-9_]*)', stripped)
            if m:
                varname = m.group(2)
                var_table[varname] = VarRecord(varname, 'EXTERNAL', lineno, 'read')
                continue

            # VAR=value assignment
            m = _RE_ASSIGN.match(stripped)
            if not m:
                continue
            varname = m.group(1)
            value = m.group(2).strip().strip('"\'')

            prov = self._classify_value_provenance(value, var_table)
            var_table[varname] = VarRecord(varname, prov, lineno, value)

    def _classify_value_provenance(
        self, value: str, var_table: Dict[str, VarRecord]
    ) -> str:
        """Determine if *value* is EXTERNAL, INTERNAL, or UNKNOWN."""
        # Positional params: $1 $2 $@ $* etc.
        if _RE_POSITIONAL.search(value):
            return 'EXTERNAL'

        # CGI / HTTP env vars used directly: $QUERY_STRING etc.
        for ref in _RE_VAR_REF.findall(value):
            upper = ref.upper()
            if any(upper.startswith(p) for p in _EXTERNAL_ENV_PREFIXES):
                return 'EXTERNAL'

        # Command substitution: $(cmd ...) or `cmd ...`
        for pat in (_RE_CMD_SUBST_DOLLAR, _RE_CMD_SUBST_BACKTICK):
            for m in pat.finditer(value):
                cmd_content = m.group(1).strip()
                cmd_name = cmd_content.split()[0].lstrip('/')
                # basename only
                cmd_name = cmd_name.rsplit('/', 1)[-1]
                if cmd_name in _EXTERNAL_CMDS:
                    return 'EXTERNAL'
                # Any command substitution that isn't provably safe = UNKNOWN
                return 'UNKNOWN'

        # Variable reference: $VAR or ${VAR}
        refs = _RE_VAR_REF.findall(value)
        if refs:
            provenances = set()
            for ref in refs:
                rec = var_table.get(ref)
                if rec:
                    provenances.add(rec.provenance)
                else:
                    provenances.add('UNKNOWN')
            if 'EXTERNAL' in provenances:
                return 'EXTERNAL'
            if 'UNKNOWN' in provenances:
                return 'UNKNOWN'
            if provenances == {'INTERNAL'}:
                return 'INTERNAL'
            return 'UNKNOWN'

        # Pure literal: no variable refs, no command substitutions
        return 'INTERNAL'

    def _classify_expr(
        self, expr: str, var_table: Dict[str, VarRecord]
    ) -> Tuple[str, List[str], Dict[str, str]]:
        """
        Classify an expression that appears in command position.

        Returns (verdict, vars_involved, {var: provenance}).
        """
        vars_involved: List[str] = []
        var_prov: Dict[str, str] = {}

        # Collect all variable references in the expression
        for ref in _RE_VAR_REF.findall(expr):
            if ref not in vars_involved:
                vars_involved.append(ref)
            rec = var_table.get(ref)
            var_prov[ref] = rec.provenance if rec else 'UNKNOWN'

        # Also check positional params
        if _RE_POSITIONAL.search(expr):
            vars_involved.append('$@/$*/$N')
            var_prov['$@/$*/$N'] = 'EXTERNAL'

        # Determine verdict
        provenances = set(var_prov.values())
        if not vars_involved:
            return 'RODATA_CONST', [], {}
        if 'EXTERNAL' in provenances:
            return 'ARG_PROPAGATED', vars_involved, var_prov
        if 'UNKNOWN' in provenances:
            return 'UNKNOWN', vars_involved, var_prov
        return 'RODATA_CONST', vars_involved, var_prov


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _main() -> None:
    import argparse
    parser = argparse.ArgumentParser(
        description="Classify exec-class sink provenance in POSIX shell scripts"
    )
    parser.add_argument('target', help='Shell script file or directory')
    parser.add_argument(
        '--flagged-only', action='store_true',
        help='Only show ARG_PROPAGATED, UNKNOWN, EVAL_SINK results',
    )
    args = parser.parse_args()

    clf = ShellSinkClassifier.from_path(args.target)
    results = clf.classify()

    if args.flagged_only:
        results = [r for r in results if r.verdict != 'RODATA_CONST']

    print(ShellSinkClassifier.report(results))


if __name__ == '__main__':
    _main()
