"""
lua_injection_analyzer.py: Python→Lua code injection detector.

Detects unsanitized user-supplied strings embedded in Lua source code via
Python format operations (str.format(), f-strings, %-formatting) before
execution by lupa LuaRuntime.execute() or subprocess calls to a Lua interpreter.

Why this exists:
1. No ablation module detected FAZ-SIEM-001 (CRITICAL): unsanitized description
   field embedded in Lua comment via .format() → \\n breaks comment → RCE via
   LuaRuntime.execute(). Required full manual source read of compiler.py + rule.py.
2. No ablation module detected FAZ-SIEM-002 (HIGH): regex capture values from user
   log input embedded in Lua string literals via .format() with no quote escaping.
3. FortiManager v8.0.0 was byte-identical to FortiAnalyzer — same 4 findings
   transferred automatically once the source was understood; an automated scanner
   would have caught both products in one pass.
4. Scope extends beyond Fortinet: any Python backend using lupa, lunatic-python,
   or cffi Lua bindings shares this vulnerability class.

Detection patterns:
  DIRECT     lua_rt.execute("...{}...".format(x)) or lua_rt.execute(f"...{x}...")
  INDIRECT   code = "...{}...".format(x); lua_rt.execute(code)
  SUBPROCESS subprocess.run(['lua', '-e', formatted_code]) or subprocess.Popen(...)

Severity:
  CRITICAL   format arg demonstrably flows from request data or function parameter
             labelled with a request-data name (description, log_str, user_input, etc.)
  HIGH       format arg is any non-literal expression (default for most findings)
  MEDIUM     subprocess invocation only (indirect exploitation path)

Usage:
    from ablation.analyzers.lua_injection_analyzer import LuaInjectionAnalyzer

    results = LuaInjectionAnalyzer.from_path('/path/to/django/app').scan()
    print(LuaInjectionAnalyzer.report(results))

CLI:
    python3 -m ablation.analyzers.lua_injection_analyzer /path/to/app
    python3 -m ablation.analyzers.lua_injection_analyzer /path/to/app --severity HIGH
"""

import ast
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    from .source_ingestion import SourceContext
except ImportError:
    from source_ingestion import SourceContext  # type: ignore

# ── Pre-filter patterns ───────────────────────────────────────────────────────

# Screens files before expensive AST parse.
_LUA_EXEC_RE = re.compile(r'\blua\w*\.(execute|eval)\s*\(', re.IGNORECASE)
_LUPA_IMPORT_RE = re.compile(r'\blupa\b|\bLuaRuntime\b|\blunatic\b')
_SUBPROCESS_LUA_RE = re.compile(r'subprocess\s*\.\s*(run|Popen|call|check_output)\s*\(')

# Known user-input variable names that escalate severity to CRITICAL.
_USER_INPUT_NAMES = frozenset({
    'description', 'user_input', 'request', 'req', 'data', 'log_str',
    'log_line', 'record', 'value', 'values', 'user_data', 'input_data',
    'body', 'payload', 'message', 'content', 'text', 'log_arr',
    'name', 'title', 'comment', 'note', 'field', 'param', 'args',
})

# Lua interpreter executable names.
_LUA_EXECUTABLES = frozenset({'lua', 'luajit', 'luac', 'lua5.1', 'lua5.2',
                               'lua5.3', 'lua5.4', 'lua5.5'})


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class LuaInjectionFinding:
    """One detected Python→Lua injection site."""
    path: Path
    rel_path: str
    cwe: str
    severity: str
    injection_type: str   # DIRECT | INDIRECT | SUBPROCESS
    exec_line: int        # line of lua.execute() or subprocess call
    exec_text: str        # source line of the execute call
    format_line: int      # line of the format operation
    format_text: str      # source line of the format operation
    var_name: str = ""    # variable name for INDIRECT paths
    description: str = ""

    def as_dict(self) -> dict:
        return {
            "path": self.rel_path,
            "cwe": self.cwe,
            "severity": self.severity,
            "type": self.injection_type,
            "exec_line": self.exec_line,
            "format_line": self.format_line,
            "description": self.description,
        }


# ── AST helpers ───────────────────────────────────────────────────────────────

def _is_format_expression(node: ast.expr) -> bool:
    """True if node produces a string with embedded variable content."""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == 'format':
            return bool(node.args or node.keywords)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
            return True
    return False


def _is_lua_execute_call(node: ast.Call) -> bool:
    """True if call looks like lua_rt.execute() or lua.eval()."""
    if not isinstance(node.func, ast.Attribute):
        return False
    if node.func.attr not in ('execute', 'eval'):
        return False
    receiver = node.func.value
    if isinstance(receiver, ast.Name):
        return 'lua' in receiver.id.lower()
    # Also match chained: LuaRuntime().execute(...)
    if isinstance(receiver, ast.Call):
        if isinstance(receiver.func, ast.Name):
            return 'lua' in receiver.func.id.lower()
    return False


def _is_subprocess_lua_call(node: ast.Call) -> bool:
    """True if call is subprocess.run/Popen/call with lua interpreter.

    Checks all command-list elements to handle wrappers like
    ['env', 'lua', ...] or ['sudo', 'lua', '-e', code].
    """
    func = node.func
    if not isinstance(func, ast.Attribute):
        return False
    if func.attr not in ('run', 'Popen', 'call', 'check_output', 'check_call'):
        return False
    if not isinstance(func.value, ast.Name) or func.value.id != 'subprocess':
        return False
    if not node.args:
        return False
    cmd = node.args[0]
    if not isinstance(cmd, ast.List) or not cmd.elts:
        return False
    for elt in cmd.elts:
        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
            if elt.value.lower() in _LUA_EXECUTABLES:
                return True
    return False


def _names_in_format_args(node: ast.expr) -> set[str]:
    """Return variable names used as format arguments."""
    names: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            names.add(child.id)
    return names


def _severity_for_format(format_node: ast.expr, assign_ctx: dict[str, tuple]) -> str:
    """Determine severity based on variable names in the format arguments."""
    arg_names = _names_in_format_args(format_node)
    # Check if the format args include any known user-input names
    if arg_names & _USER_INPUT_NAMES:
        return "CRITICAL"
    # Check if any format arg comes from a function parameter passed as
    # user-controlled data (heuristic: single-word names common in Django views)
    return "HIGH"


# ── Per-function scope visitor ────────────────────────────────────────────────

class _FuncScopeVisitor(ast.NodeVisitor):
    """
    Visits a single function body.

    Tracks variable assignments and detects Lua injection patterns.
    Does NOT recurse into nested function/class definitions — those get
    their own fresh scope when the file-level visitor encounters them.
    """

    def __init__(self, source_lines: list[str]):
        self._lines = source_lines
        self.findings: list[dict] = []
        # var_name -> (lineno, format_expr_node)
        self._assigns: dict[str, tuple[int, ast.expr]] = {}

    def _src_line(self, lineno: int) -> str:
        if 1 <= lineno <= len(self._lines):
            return self._lines[lineno - 1].rstrip()
        return ""

    def visit_Assign(self, node: ast.Assign) -> None:
        if _is_format_expression(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._assigns[target.id] = (node.lineno, node.value)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        # Handle: code += f"...{x}..."
        if isinstance(node.op, ast.Add) and _is_format_expression(node.value):
            if isinstance(node.target, ast.Name):
                self._assigns[node.target.id] = (node.lineno, node.value)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if _is_lua_execute_call(node):
            self._check_lua_call(node)
        elif _is_subprocess_lua_call(node):
            self._check_subprocess_call(node)
        self.generic_visit(node)

    def _check_lua_call(self, call: ast.Call) -> None:
        for arg in call.args:
            if _is_format_expression(arg):
                sev = _severity_for_format(arg, self._assigns)
                self.findings.append({
                    'injection_type': 'DIRECT',
                    'exec_line': call.lineno,
                    'exec_text': self._src_line(call.lineno),
                    'format_line': arg.lineno,
                    'format_text': self._src_line(arg.lineno),
                    'format_node': arg,
                    'severity': sev,
                    'var_name': '',
                })
            elif isinstance(arg, ast.Name) and arg.id in self._assigns:
                assign_lineno, assign_node = self._assigns[arg.id]
                sev = _severity_for_format(assign_node, self._assigns)
                self.findings.append({
                    'injection_type': 'INDIRECT',
                    'exec_line': call.lineno,
                    'exec_text': self._src_line(call.lineno),
                    'format_line': assign_lineno,
                    'format_text': self._src_line(assign_lineno),
                    'format_node': assign_node,
                    'severity': sev,
                    'var_name': arg.id,
                })

    def _check_subprocess_call(self, call: ast.Call) -> None:
        # Check for format expressions anywhere in the command list args
        cmd = call.args[0]
        if not isinstance(cmd, ast.List):
            return
        for elt in cmd.elts:
            if _is_format_expression(elt):
                sev = _severity_for_format(elt, self._assigns)
                self.findings.append({
                    'injection_type': 'SUBPROCESS',
                    'exec_line': call.lineno,
                    'exec_text': self._src_line(call.lineno),
                    'format_line': elt.lineno,
                    'format_text': self._src_line(elt.lineno),
                    'format_node': elt,
                    'severity': sev if sev == 'CRITICAL' else 'MEDIUM',
                    'var_name': '',
                })

    # Prevent recursion into nested defs — they get their own scope.
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        pass

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        pass


# ── File-level visitor ────────────────────────────────────────────────────────

class _FileVisitor(ast.NodeVisitor):
    """
    Visits a full module AST, spawning fresh _FuncScopeVisitor instances
    for each function definition encountered.
    """

    def __init__(self, source_lines: list[str]):
        self._lines = source_lines
        self.raw_findings: list[dict] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        scope = _FuncScopeVisitor(self._lines)
        for child in ast.iter_child_nodes(node):
            scope.visit(child)
        self.raw_findings.extend(scope.findings)
        # Still recurse into the body to handle nested functions
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]


# ── Main analyzer ─────────────────────────────────────────────────────────────

class LuaInjectionAnalyzer:
    """
    Python→Lua code injection scanner.

    Operates on a directory of Python source files. Uses Python's ast module
    for precise analysis; pre-filters files with regex to avoid parsing every
    file in large codebases.
    """

    #: Warn when file count exceeds this threshold to catch accidental root scans.
    MAX_FILES_WARN = 10_000

    def __init__(
        self,
        root: Path,
        rel_base: Optional[Path] = None,
        extra_user_input_names: Optional[frozenset] = None,
        max_files: Optional[int] = None,
    ):
        self._root = root
        self._rel_base = rel_base or root
        self._extra_names: frozenset = extra_user_input_names or frozenset()
        self._max_files = max_files

    @classmethod
    def from_path(
        cls,
        path: str | Path,
        extra_user_input_names: Optional[frozenset] = None,
    ) -> "LuaInjectionAnalyzer":
        p = Path(path)
        return cls(root=p, rel_base=p, extra_user_input_names=extra_user_input_names)

    @classmethod
    def from_context(
        cls,
        ctx: SourceContext,
        extra_user_input_names: Optional[frozenset] = None,
    ) -> "LuaInjectionAnalyzer":
        return cls(
            root=ctx.root,
            rel_base=ctx.root,
            extra_user_input_names=extra_user_input_names,
        )

    def _rel(self, path: Path) -> str:
        try:
            return str(path.relative_to(self._rel_base))
        except ValueError:
            return str(path)

    def _should_scan(self, text: str) -> bool:
        """Quick pre-filter: only parse files that could have Lua injection."""
        if _LUPA_IMPORT_RE.search(text):
            return True
        if _LUA_EXEC_RE.search(text):
            return True
        if _SUBPROCESS_LUA_RE.search(text) and 'lua' in text.lower():
            return True
        return False

    def _scan_file(self, path: Path) -> list[LuaInjectionFinding]:
        try:
            text = path.read_text(encoding='utf-8', errors='replace')
        except OSError as exc:
            import warnings
            warnings.warn(f"LuaInjectionAnalyzer: skipped {path}: {exc}", stacklevel=3)
            return []

        if not self._should_scan(text):
            return []

        source_lines = text.splitlines()
        try:
            tree = ast.parse(text, filename=str(path))
        except SyntaxError as exc:
            import warnings
            warnings.warn(
                f"LuaInjectionAnalyzer: could not parse {path}: {exc}",
                stacklevel=3,
            )
            return []

        visitor = _FileVisitor(source_lines)
        visitor.visit(tree)

        findings: list[LuaInjectionFinding] = []
        rel = self._rel(path)
        _effective_user_names = _USER_INPUT_NAMES | self._extra_names
        for raw in visitor.raw_findings:
            inj_type = raw['injection_type']
            # Re-evaluate severity with effective user-input name set
            fmt_node = raw['format_node']
            arg_names = _names_in_format_args(fmt_node)
            if arg_names & _effective_user_names:
                sev = "CRITICAL"
            elif inj_type == "SUBPROCESS":
                sev = "MEDIUM"
            else:
                sev = "HIGH"
            cwe = "CWE-94"  # Code injection via Lua execution

            if inj_type == 'DIRECT':
                desc = (
                    f"Unsanitized format expression passed directly to lua.execute(); "
                    f"embedded values may break out of surrounding Lua syntax "
                    f"(e.g. \\n in a comment, '\"' in a string literal)"
                )
            elif inj_type == 'INDIRECT':
                vn = raw.get('var_name', '')
                desc = (
                    f"Variable '{vn}' assigned from format expression "
                    f"(line {raw['format_line']}) then passed to lua.execute(); "
                    f"intermediate assignment does not sanitize"
                )
            else:
                desc = (
                    f"Format expression in subprocess lua command list; "
                    f"embedded values may inject arbitrary Lua"
                )

            findings.append(LuaInjectionFinding(
                path=path,
                rel_path=rel,
                cwe=cwe,
                severity=sev,
                injection_type=inj_type,
                exec_line=raw['exec_line'],
                exec_text=raw['exec_text'],
                format_line=raw['format_line'],
                format_text=raw['format_text'],
                var_name=raw.get('var_name', ''),
                description=desc,
            ))
        return findings

    def scan(self) -> list[LuaInjectionFinding]:
        """
        Scan all Python files under root for Lua injection patterns.

        Returns findings sorted: CRITICAL first, then HIGH, then by path+line.
        """
        import warnings
        findings: list[LuaInjectionFinding] = []
        file_count = 0
        for path in self._root.rglob("*.py"):
            file_count += 1
            if self._max_files is not None and file_count > self._max_files:
                warnings.warn(
                    f"LuaInjectionAnalyzer: exceeded max_files={self._max_files}; "
                    f"scan truncated at {self._root}",
                    stacklevel=2,
                )
                break
            if file_count == self.MAX_FILES_WARN:
                warnings.warn(
                    f"LuaInjectionAnalyzer: scanning {file_count}+ files under "
                    f"{self._root} — consider passing max_files= to limit scope",
                    stacklevel=2,
                )
            findings.extend(self._scan_file(path))

        _order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        findings.sort(key=lambda f: (_order.get(f.severity, 9), f.rel_path, f.exec_line))
        return findings

    @staticmethod
    def report(findings: list[LuaInjectionFinding]) -> str:
        if not findings:
            return "LuaInjectionAnalyzer: no findings."

        counts: dict[str, int] = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        lines = [
            "Python→Lua Injection Analysis",
            "=" * 70,
        ]
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if counts.get(sev):
                lines.append(f"  {sev:<10}: {counts[sev]}")
        lines.append("")

        current_sev = None
        for f in findings:
            if f.severity != current_sev:
                current_sev = f.severity
                lines.append(f"── {current_sev} ──────────────────────────────────────")

            lines.append(f"  {f.rel_path}:{f.exec_line}  [{f.injection_type}]  {f.cwe}")
            lines.append(f"    Exec:   {f.exec_text.strip()}")
            if f.format_line != f.exec_line:
                lines.append(f"    Format: {f.format_text.strip()}  (line {f.format_line})")
            if f.var_name:
                lines.append(f"    Via:    variable '{f.var_name}'")
            lines.append(f"    {f.description}")
            lines.append("")

        return "\n".join(lines)


# ── CLI ───────────────────────────────────────────────────────────────────────

def _main() -> int:
    import argparse
    parser = argparse.ArgumentParser(
        description="Scan Python source for Lua injection patterns"
    )
    parser.add_argument("path", help="Root directory to scan")
    parser.add_argument(
        "--severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        help="Filter to this severity or higher",
    )
    args = parser.parse_args()

    analyzer = LuaInjectionAnalyzer.from_path(args.path)
    findings = analyzer.scan()

    if args.severity:
        _thresh = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        findings = [f for f in findings
                    if _thresh.get(f.severity, 9) <= _thresh[args.severity]]

    print(LuaInjectionAnalyzer.report(findings))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(_main())
