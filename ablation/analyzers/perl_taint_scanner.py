"""
perl_taint_scanner.py: static taint analysis for Perl shell injection (CWE-78).

3 things this fills that weren't possible before:

1. **Find qx//+system() injection in Perl layers that sit above setuid ELFs.**
   RSCT, IBM HMC, and many embedded Linux targets ship thick .pm/.pl layers
   that wrap root-privileged binaries. TaintTracker is ELF-only; it never sees
   these scripts. PerlTaintScanner closes the gap: it finds shell sinks with
   interpolated variables and traces those variables to their origin (CLI args,
   function parameters, or internal state).

2. **Detect Perl-specific sanitization patterns.**
   Perl codebases use sanitization idioms that a generic grep cannot recognize:
   quotemeta(), single-quote wrapping ("'" . join("' '", @args) . "'"), and
   s/'/ /g substitutions before shell expansion. PerlTaintScanner recognizes
   all three and reports SANITIZED rather than false-positiving on them.

3. **Cross-file caller resolution for PARAM sources.**
   When a sink variable comes from shift(@_) (a function parameter), the scanner
   resolves one hop back into caller files to determine whether the caller passes
   @ARGV or Getopt-derived values. This catches the ERRM_cli_utils.pm pattern
   where the injection variable enters via a CLI script (rmcondition) that the
   .pm file itself never touches.

Verdict classes:
  INJECTABLE     — user CLI arg (ARGV/Getopt) → unsanitized → shell sink
  SANITIZED      — source is CLI arg but sanitization detected before sink
  PARAM_UNKNOWN  — function parameter source confirmed; callers not in scan set
  INTERNAL       — source is internal state (no user path confirmed)
  UNKNOWN        — source could not be resolved within look-back window

Usage::

    from ablation.analyzers.perl_taint_scanner import PerlTaintScanner

    # Scan a directory of .pm/.pl files
    scanner = PerlTaintScanner.from_path('/tmp/hmc_new_rpms/rsct.core/opt/rsct')
    results = scanner.scan()
    print(scanner.report(results))

    # Scan specific files
    scanner = PerlTaintScanner.from_files([
        '/opt/rsct/pm/ERRM_cli_utils.pm',
        '/opt/rsct/bin/rmcondition',
    ])
    injectable = [r for r in scanner.scan() if r.verdict == 'INJECTABLE']

CLI::
    python3 -m ablation.analyzers.perl_taint_scanner /path/to/dir
    python3 -m ablation.analyzers.perl_taint_scanner /path/to/dir --injectable-only
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


# ── regex library ──────────────────────────────────────────────────────────────

# Shell sink patterns with variable interpolation.
# Groups: (line_content) — we extract vars separately.
_RE_BACKTICK = re.compile(
    r'(?:^|[^\'\\])`([^`]*\$[^`]*)`',
    re.MULTILINE,
)
_RE_QX = re.compile(
    r'\bqx\s*(?P<delim>[/{!|#])(?P<cmd>[^]*?)\$[^]*?)(?P=delim)',
    re.MULTILINE,
)
# Simpler qx// scanner: find any qx with a $ inside
_RE_QX_SIMPLE = re.compile(
    r'\bqx\s*\{([^}]*\$[^}]*)\}|\bqx\s*/([^/]*\$[^/]*)/'
    r'|\bqx\s*!([^!]*\$[^!]*)!'
    r'|\bqx\s*\|([^|]*\$[^|]*)\|',
)
_RE_SYSTEM = re.compile(
    r'\bsystem\s*\(\s*"([^"]*\$[^"]*)"',
)
_RE_OPEN_PIPE = re.compile(
    r'\bopen\s*\(\s*\w+\s*,\s*"([^"]*\$[^"]*\|[^"]*)"',
)

# Variable extraction from a command string
_RE_VARS = re.compile(r'\$\{?(\w+)\}?')

# Source patterns for variable assignment
_RE_SHIFT      = re.compile(r'^\s*(?:my\s+)?\$(\w+)\s*=\s*shift(?:\(@_\)|)')
_RE_GETOPT_VAR = re.compile(
    r'(?:my\s+)?\$(\w+)\s*=\s*(?:\(\s*)?\$(?:opt(?:s|ion)?s?|opts?)\{[\'"]?(\w+)[\'"]?\}'
)
_RE_ARGV       = re.compile(r'(?:my\s+)?\$(\w+)\s*=\s*\$ARGV\[')
_RE_STDIN      = re.compile(r'(?:my\s+)?\$(\w+)\s*=\s*<STDIN>')
_RE_GETOPTS    = re.compile(r'\b(?:getopts|GetOptions)\b')

# Sanitization patterns
_RE_QUOTEMETA  = re.compile(r'\$(\w+)\s*=\s*quotemeta\s*\(\s*\$(\w+)\s*\)')
_RE_SQUOTE_WRAP = re.compile(
    # "'" . join("' '", @args) . "'" — single-quote wrapping idiom
    r"""["']\s*\.\s*join\s*\(\s*["']'\s+'["']\s*,"""
)
_RE_STRIP_SQUOTE = re.compile(
    # $var =~ s/'/ /g or $var =~ s/['"...]//g
    r"""\$(\w+)\s*=~\s*s/['"]"""
)


@dataclass
class SinkHit:
    file: str
    line_no: int
    line: str
    var: str                    # the interpolated variable name
    sink_type: str              # 'backtick' | 'qx' | 'system' | 'open_pipe'
    verdict: str                # INJECTABLE / SANITIZED / PARAM_UNKNOWN / INTERNAL / UNKNOWN
    source_desc: str = ""       # human-readable source explanation
    sanitization: str = ""      # description of sanitization found, if any
    caller_file: Optional[str] = None  # file where PARAM resolved to ARGV source

    def fmt(self) -> str:
        tag = {
            'INJECTABLE':    '[!] INJECTABLE',
            'SANITIZED':     '[-] SANITIZED ',
            'PARAM_UNKNOWN': '[?] PARAM     ',
            'INTERNAL':      '[.] INTERNAL  ',
            'UNKNOWN':       '[?] UNKNOWN   ',
        }.get(self.verdict, f'[?] {self.verdict}')
        loc = f"{self.file}:{self.line_no}"
        src = f"  src: {self.source_desc}" if self.source_desc else ""
        san = f"  san: {self.sanitization}" if self.sanitization else ""
        return f"{tag}  ${self.var}  [{self.sink_type}]  {loc}{src}{san}"


class _FileAnalysis:
    """Parsed representation of a single Perl file."""

    def __init__(self, path: Path):
        self.path = path
        self.lines: List[str] = path.read_text(errors='replace').splitlines()
        self._funcs: Dict[str, Tuple[int, int]] = {}  # name → (start_line, end_line)
        self._getopts_funcs: Set[str] = set()         # function names that call getopts
        self._parse_functions()

    def _parse_functions(self):
        """Find sub name → (start, end) line ranges."""
        starts: List[Tuple[int, str]] = []
        for i, line in enumerate(self.lines):
            m = re.match(r'^\s*sub\s+(\w+)', line)
            if m:
                starts.append((i, m.group(1)))
        for idx, (start, name) in enumerate(starts):
            end = starts[idx + 1][0] - 1 if idx + 1 < len(starts) else len(self.lines) - 1
            self._funcs[name] = (start, end)
            # check if getopts/GetOptions called within this sub
            for ln in self.lines[start:end + 1]:
                if _RE_GETOPTS.search(ln):
                    self._getopts_funcs.add(name)

    def func_for_line(self, lineno: int) -> Optional[str]:
        """Return the sub name containing lineno (0-indexed)."""
        for name, (s, e) in self._funcs.items():
            if s <= lineno <= e:
                return name
        return None

    def func_range(self, name: str) -> Tuple[int, int]:
        return self._funcs.get(name, (0, len(self.lines) - 1))

    def lines_in_func(self, name: Optional[str]) -> List[Tuple[int, str]]:
        """Return (lineno, line) pairs for lines within the named sub."""
        if name is None:
            return [(i, l) for i, l in enumerate(self.lines)]
        s, e = self.func_range(name)
        return [(i, self.lines[i]) for i in range(s, e + 1)]


class PerlTaintScanner:
    """Static shell-injection taint scanner for Perl .pl/.pm files."""

    def __init__(self, files: List[Path]):
        self._files = files
        self._analyses: Dict[str, _FileAnalysis] = {}
        for f in files:
            try:
                self._analyses[str(f)] = _FileAnalysis(f)
            except Exception:
                pass

    @classmethod
    def from_path(cls, path: str | Path) -> 'PerlTaintScanner':
        """Recursively find all .pl and .pm files under path."""
        root = Path(path)
        if root.is_file():
            return cls([root])
        files = list(root.rglob('*.pl')) + list(root.rglob('*.pm'))
        return cls(files)

    @classmethod
    def from_files(cls, paths: List[str | Path]) -> 'PerlTaintScanner':
        return cls([Path(p) for p in paths])

    # ── public API ─────────────────────────────────────────────────────────────

    def scan(self) -> List[SinkHit]:
        hits: List[SinkHit] = []
        for filepath, analysis in self._analyses.items():
            hits.extend(self._scan_file(analysis))
        # Sort by verdict severity
        order = {'INJECTABLE': 0, 'PARAM_UNKNOWN': 1, 'UNKNOWN': 2,
                 'SANITIZED': 3, 'INTERNAL': 4}
        hits.sort(key=lambda h: (order.get(h.verdict, 9), h.file, h.line_no))
        return hits

    def report(self, hits: Optional[List[SinkHit]] = None) -> str:
        if hits is None:
            hits = self.scan()
        if not hits:
            return "PerlTaintScanner: no shell sinks with variable interpolation found."
        lines = ["PerlTaintScanner results:", ""]
        counts: Dict[str, int] = {}
        for h in hits:
            lines.append(h.fmt())
            counts[h.verdict] = counts.get(h.verdict, 0) + 1
        lines += ["", "Summary: " + ", ".join(
            f"{v}={n}" for v, n in sorted(counts.items())
        )]
        return "\n".join(lines)

    # ── internal scanning ─────────────────────────────────────────────────────

    def _scan_file(self, analysis: _FileAnalysis) -> List[SinkHit]:
        hits: List[SinkHit] = []
        text = "\n".join(analysis.lines)

        # Collect sink positions: (line_no, var, sink_type, full_cmd_str)
        sinks: List[Tuple[int, str, str, str]] = []

        for m in _RE_BACKTICK.finditer(text):
            cmd = m.group(1)
            line_no = text[:m.start()].count('\n')
            for var in _RE_VARS.findall(cmd):
                sinks.append((line_no, var, 'backtick', cmd))

        for m in _RE_QX_SIMPLE.finditer(text):
            cmd = next(g for g in m.groups() if g is not None)
            line_no = text[:m.start()].count('\n')
            for var in _RE_VARS.findall(cmd):
                sinks.append((line_no, var, 'qx', cmd))

        for m in _RE_SYSTEM.finditer(text):
            cmd = m.group(1)
            line_no = text[:m.start()].count('\n')
            for var in _RE_VARS.findall(cmd):
                sinks.append((line_no, var, 'system', cmd))

        for m in _RE_OPEN_PIPE.finditer(text):
            cmd = m.group(1)
            line_no = text[:m.start()].count('\n')
            for var in _RE_VARS.findall(cmd):
                sinks.append((line_no, var, 'open_pipe', cmd))

        seen: Set[Tuple[int, str]] = set()
        for line_no, var, sink_type, cmd in sinks:
            key = (line_no, var)
            if key in seen:
                continue
            seen.add(key)
            # Skip Perl special vars ($_, $!, $CTBINDIR, etc.)
            if var in ('_', 'ENV', '0', '1', 'CTBINDIR', 'DELIMITER',
                       'DELIMITERI', 'DELIMITERO', 'main'):
                continue
            hit = self._classify(analysis, line_no, var, sink_type)
            hits.append(hit)

        return hits

    def _classify(
        self,
        analysis: _FileAnalysis,
        sink_line: int,
        var: str,
        sink_type: str,
    ) -> SinkHit:
        func_name = analysis.func_for_line(sink_line)
        func_lines = analysis.lines_in_func(func_name)
        raw_line = analysis.lines[sink_line] if sink_line < len(analysis.lines) else ""

        # Walk backward from sink_line within the function to find var source
        source_verdict = 'UNKNOWN'
        source_desc = ""
        sanitized = ""

        # Check sanitization applied to this var anywhere before the sink
        sanitized = self._check_sanitization(func_lines, var, sink_line)

        for lineno, line in reversed(func_lines):
            if lineno >= sink_line:
                continue  # only look back

            # shift(@_) / shift
            m = _RE_SHIFT.match(line)
            if m and m.group(1) == var:
                source_verdict = 'PARAM'
                source_desc = f"function param (shift) in sub '{func_name}'"
                break

            # $var = $opts{key} or $options{key}
            m = _RE_GETOPT_VAR.search(line)
            if m and m.group(1) == var:
                if func_name in analysis._getopts_funcs or self._has_getopts_in_func(
                    analysis, func_name
                ):
                    source_verdict = 'CLI_ARG'
                    source_desc = f"Getopt/getopts flag (\\${var} = $opts{{...}})"
                    break
                # $opts{} without explicit getopts in same func — treat as CLI
                source_verdict = 'CLI_ARG'
                source_desc = f"option hash (\\${var} = $opts{{...}})"
                break

            # $var = $ARGV[n]
            if _RE_ARGV.search(line) and re.search(
                r'(?:my\s+)?\$' + re.escape(var) + r'\s*=\s*\$ARGV\[', line
            ):
                source_verdict = 'CLI_ARG'
                source_desc = f"direct ARGV (\\${var} = $ARGV[...])"
                break

            # $var = <STDIN>
            if _RE_STDIN.search(line) and re.search(
                r'(?:my\s+)?\$' + re.escape(var) + r'\s*=\s*<STDIN>', line
            ):
                source_verdict = 'USER_INPUT'
                source_desc = f"stdin read (\\${var} = <STDIN>)"
                break

        # Resolve PARAM → check callers in other files
        caller_file: Optional[str] = None
        if source_verdict == 'PARAM' and func_name:
            caller_source, caller_file = self._resolve_param_callers(func_name, var)
            if caller_source:
                source_verdict = caller_source
                source_desc += f" → {caller_file or 'unknown'}: {source_verdict}"

        # Map to final verdict
        if source_verdict in ('CLI_ARG', 'USER_INPUT'):
            verdict = 'SANITIZED' if sanitized else 'INJECTABLE'
        elif source_verdict == 'PARAM':
            verdict = 'SANITIZED' if sanitized else 'PARAM_UNKNOWN'
        elif source_verdict == 'UNKNOWN':
            verdict = 'SANITIZED' if sanitized else 'UNKNOWN'
        else:
            verdict = 'INTERNAL'

        return SinkHit(
            file=str(analysis.path),
            line_no=sink_line + 1,
            line=raw_line.rstrip(),
            var=var,
            sink_type=sink_type,
            verdict=verdict,
            source_desc=source_desc,
            sanitization=sanitized,
            caller_file=caller_file,
        )

    def _check_sanitization(
        self,
        func_lines: List[Tuple[int, str]],
        var: str,
        sink_line: int,
    ) -> str:
        """Return a description of any sanitization applied to var before sink_line."""
        for lineno, line in func_lines:
            if lineno >= sink_line:
                break
            # quotemeta($var) or $var = quotemeta(...)
            if re.search(r'quotemeta\s*\(\s*\$' + re.escape(var), line):
                return "quotemeta()"
            # Single-quote wrapping idiom
            if _RE_SQUOTE_WRAP.search(line):
                return "single-quote wrap (join idiom)"
            # s/'/ /g applied to the var
            if re.search(r'\$' + re.escape(var) + r'\s*=~\s*s/', line):
                return f"regex substitution (s/.../ on ${var})"
            # Explicit strip of shell metacharacters
            if re.search(
                r'\$' + re.escape(var) + r'''\s*=~\s*s/[^'"]*[;&|`$]''', line
            ):
                return "metachar strip"
        return ""

    def _has_getopts_in_func(self, analysis: _FileAnalysis, func_name: Optional[str]) -> bool:
        if func_name is None:
            return any(_RE_GETOPTS.search(l) for l in analysis.lines)
        return func_name in analysis._getopts_funcs

    def _resolve_param_callers(
        self, func_name: str, var: str
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Search other loaded files for callers of func_name.
        Return (source_verdict, caller_file) if resolved, else (None, None).
        """
        for filepath, anal in self._analyses.items():
            for i, line in enumerate(anal.lines):
                # Look for: func_name($something, ...) where $something might be @ARGV-derived
                if func_name not in line:
                    continue
                m = re.search(r'\b' + re.escape(func_name) + r'\s*\(([^)]*)\)', line)
                if not m:
                    continue
                args_str = m.group(1)
                # Extract first positional arg variable
                arg_vars = _RE_VARS.findall(args_str)
                if not arg_vars:
                    continue
                call_var = arg_vars[0]
                # Now look for how call_var is assigned in the caller's scope
                func_at_call = anal.func_for_line(i)
                func_lines_caller = anal.lines_in_func(func_at_call)
                for j, cline in reversed(func_lines_caller):
                    if j >= i:
                        continue
                    if _RE_ARGV.search(cline) and re.search(
                        r'\$' + re.escape(call_var) + r'\s*=.*\$ARGV', cline
                    ):
                        return ('CLI_ARG', filepath)
                    if re.search(
                        r'(?:my\s+)?\$' + re.escape(call_var) + r'\s*=\s*shift', cline
                    ):
                        # shift in caller = came from caller's @ARGV or another param
                        pass
                    if _RE_GETOPT_VAR.search(cline):
                        m2 = _RE_GETOPT_VAR.search(cline)
                        if m2 and m2.group(1) == call_var:
                            return ('CLI_ARG', filepath)
        return (None, None)


# ── CLI entry point ────────────────────────────────────────────────────────────

def _main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description='PerlTaintScanner: Perl shell injection detector')
    ap.add_argument('path', help='File or directory to scan')
    ap.add_argument('--injectable-only', action='store_true',
                    help='Show only INJECTABLE findings')
    ap.add_argument('--no-internal', action='store_true',
                    help='Hide INTERNAL and SANITIZED findings')
    args = ap.parse_args()

    scanner = PerlTaintScanner.from_path(args.path)
    hits = scanner.scan()

    if args.injectable_only:
        hits = [h for h in hits if h.verdict == 'INJECTABLE']
    elif args.no_internal:
        hits = [h for h in hits if h.verdict not in ('INTERNAL', 'SANITIZED')]

    print(scanner.report(hits))


if __name__ == '__main__':
    _main()
