"""
source_taint_tracker.py: inter-procedural taint path tracer for source RE.

Implements backward slicing from dangerous sinks to HTTP route handlers (trust
boundaries). For each sink identified by SourceSinkScanner, walks the call graph
backward until a route handler is reached or the graph is exhausted. Each
confirmed path is a TaintPath: a chain of (file, line, function) hops from
the route handler down to the sink.

Analogous to TaintTracker (x86/ARM/MIPS) in binary RE: same backward-slice
from sink model, same CONFIRMED/PLAUSIBLE verdict system. Operates on regex-
extracted call graphs instead of disassembled instruction operands.

Trust boundary: any file under pages/api/ or app/api/ that exports a default
handler function. These files receive HTTP requests (req.body, req.query, etc.)
and are the source of all user-controlled data in Next.js applications.

Confidence levels:
  DIRECT  : sink is inside a route handler (0 hops, highest confidence)
  HIGH    : route handler → 1 intermediate → sink
  MEDIUM  : route handler → 2 intermediates → sink
  LOW     : route handler → 3+ intermediates → sink (some regex FP risk)

Usage:
    from ablation.analyzers.source_ingestion import SourceContext
    from ablation.analyzers.source_sink_scanner import SourceSinkScanner, SinkHit
    from ablation.analyzers.source_taint_tracker import SourceTaintTracker

    ctx = SourceContext.from_path("/tmp/langfuse")

    # Option 1: run full pipeline
    tracker = SourceTaintTracker.from_context(ctx)
    tracker.build()
    scanner = SourceSinkScanner.from_context(ctx)
    sinks = [h for h in scanner.scan() if h.severity in ("CRITICAL", "HIGH")]
    paths = tracker.trace_all(sinks)
    print(tracker.report(paths))

    # Option 2: trace a single known sink
    paths = tracker.trace_to_source(
        sink_file=ctx.repo_root / "packages/in-app-agent-sandbox-runtime/src/server.ts",
        sink_line=330,
    )

CLI:
    python3 -m ablation.analyzers.source_taint_tracker /tmp/langfuse
    python3 -m ablation.analyzers.source_taint_tracker /tmp/langfuse --severity HIGH
"""

import re
import sys
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    from .source_ingestion import SourceContext
    from .source_sink_scanner import SourceSinkScanner, SinkHit
except ImportError:
    from source_ingestion import SourceContext
    from source_sink_scanner import SourceSinkScanner, SinkHit

# ── regex patterns for call graph construction ────────────────────────────────

# Named function declaration: function foo(  /  async function foo(
_FUNC_DECL = re.compile(
    r"^[ \t]*(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*[(<]",
    re.MULTILINE,
)

# Arrow / const function assignment: const foo = (  /  export const foo = async (
_FUNC_ASSIGN = re.compile(
    r"^[ \t]*(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:\([^)]*\)|[a-zA-Z_]\w*)\s*=>",
    re.MULTILINE,
)

# Class method: methodName(  (indented, not `function` keyword)
_CLASS_METHOD = re.compile(
    r"^[ \t]{2,}(?:(?:public|private|protected|static|async|override)\s+)*(\w+)\s*\([^)]*\)\s*(?::\s*[\w<>\[\]|&, ]+\s*)?\{",
    re.MULTILINE,
)

# Default export: export default function handler(  /  export default async function(
_DEFAULT_EXPORT = re.compile(
    r"^(?:export\s+default\s+(?:async\s+)?function\s*(?:\w+)?\s*\(|export\s+default\s+handler)",
    re.MULTILINE,
)

# Named function call: foo(  /  await foo(  /  return foo(
# Excludes: if/for/while/switch (keywords), import/require (module ops)
_CALL_SITE = re.compile(
    r"(?<!['\"`#/])\b(?!(?:if|else|for|while|switch|return|await|new|import|require|typeof|instanceof|delete|void|throw|catch|class|interface|type|enum|namespace)\b)(\w{2,})\s*\(",
)

# Import statement: import { X, Y } from './path'
_IMPORT_NAMED = re.compile(
    r"^import\s+\{([^}]+)\}\s+from\s+['\"]([^'\"]+)['\"]",
    re.MULTILINE,
)
_IMPORT_DEFAULT = re.compile(
    r"^import\s+(\w+)\s+from\s+['\"]([^'\"]+)['\"]",
    re.MULTILINE,
)
_IMPORT_STAR = re.compile(
    r"^import\s+\*\s+as\s+(\w+)\s+from\s+['\"]([^'\"]+)['\"]",
    re.MULTILINE,
)

# Source markers: expressions that produce user-controlled data
_SOURCE_PATTERNS: list[re.Pattern] = [
    re.compile(r"\breq\.(body|query|params|headers)\b"),
    re.compile(r"\brequest\.(body|json|form|args|query_params)\b"),
    re.compile(r"\bz\.unknown\(\)"),
    re.compile(r"\bJSON\.parse\("),
    re.compile(r"\breadJsonBody\b"),  # Langfuse-specific
]

# Route handler markers (trust boundary entry points)
_ROUTE_MARKERS: list[re.Pattern] = [
    re.compile(r"export\s+default\s+(?:async\s+)?function"),
    re.compile(r"export\s+const\s+(?:GET|POST|PUT|DELETE|PATCH)\s*="),
    re.compile(r"export\s+default\s+(?:async\s+)?handler"),
    re.compile(r"router\.(get|post|put|delete|patch)\s*\("),
    re.compile(r"app\.(get|post|put|delete|patch)\s*\("),
    re.compile(r"@(app|router)\.(get|post|put|delete|patch)"),
]

# Route file path patterns
_ROUTE_PATH_PATTERNS: list[re.Pattern] = [
    re.compile(r"pages[/\\]api[/\\]"),
    re.compile(r"app[/\\]api[/\\].*route\.(ts|js)$"),
    re.compile(r"routes?[/\\].*\.(ts|js)$"),
    re.compile(r"controllers?[/\\].*\.(ts|js)$"),
]

# Max BFS depth to avoid infinite loops
_MAX_HOP_DEPTH = 6
_MAX_CALLERS_PER_FUNC = 50


# ── data structures ───────────────────────────────────────────────────────────

@dataclass
class FuncDef:
    """One function definition."""
    name: str
    file: Path
    line: int       # 1-indexed line where definition starts
    is_route: bool  # True if this is a route handler


@dataclass
class TaintHop:
    """One step in a taint path."""
    func_name: str
    file: Path
    line: int
    rel_path: str

    def __str__(self) -> str:
        return f"{self.rel_path}:{self.line}  {self.func_name}()"


@dataclass
class TaintPath:
    """A confirmed or plausible taint path from route handler to sink."""
    sink: SinkHit
    hops: list[TaintHop]    # [route_handler, ..., func_containing_sink]
    confidence: str          # DIRECT | HIGH | MEDIUM | LOW
    has_source: bool         # True if a source marker (req.body etc.) was found in the path

    @property
    def depth(self) -> int:
        return len(self.hops)

    def as_dict(self) -> dict:
        return {
            "sink": self.sink.as_dict(),
            "confidence": self.confidence,
            "has_source": self.has_source,
            "depth": self.depth,
            "path": [{"func": h.func_name, "file": h.rel_path, "line": h.line} for h in self.hops],
        }


def _confidence_from_depth(depth: int) -> str:
    if depth == 0:
        return "DIRECT"
    if depth == 1:
        return "HIGH"
    if depth == 2:
        return "MEDIUM"
    return "LOW"


# ── call graph builder ────────────────────────────────────────────────────────

class CallGraph:
    """
    Lightweight inter-procedural call graph built from regex-extracted
    function definitions and call sites.

    Indexed for backward traversal: callee_name → [FuncDef of callers].
    """

    def __init__(self):
        # name → list of definitions (there may be multiple across files)
        self.func_defs: dict[str, list[FuncDef]] = {}
        # (file, func_name) → set of callee names found in the function body
        self.callees: dict[tuple[Path, str], set[str]] = {}
        # callee_name → list of (caller_file, caller_func_name) — inverted index
        self.callers_of: dict[str, list[tuple[Path, str]]] = {}
        # (file, line) → func_name that contains this line
        self._line_to_func: dict[Path, list[tuple[int, str]]] = {}

    def _extract_func_defs(self, path: Path, text: str) -> list[tuple[int, str]]:
        """Extract (line_number, func_name) for all function definitions in text."""
        lines = text.splitlines()
        defs: list[tuple[int, str]] = []

        for pattern in [_FUNC_DECL, _FUNC_ASSIGN, _CLASS_METHOD]:
            for m in pattern.finditer(text):
                name = m.group(1)
                # Skip common non-function words that slip through
                if name in ("if", "else", "for", "while", "switch", "return",
                            "const", "let", "var", "type", "interface", "class",
                            "enum", "import", "export", "from", "async", "await"):
                    continue
                line_no = text.count("\n", 0, m.start()) + 1
                defs.append((line_no, name))

        defs.sort()
        return defs

    def _func_at_line(self, path: Path, target_line: int) -> Optional[str]:
        """Return the name of the function that contains target_line."""
        defs = self._line_to_func.get(path, [])
        result = None
        for line_no, name in defs:
            if line_no <= target_line:
                result = name
            else:
                break
        return result

    def _is_route_file(self, path: Path) -> bool:
        rel = str(path).replace("\\", "/")
        return any(p.search(rel) for p in _ROUTE_PATH_PATTERNS)

    def _file_has_source(self, path: Path, func_name: str, text: str) -> bool:
        """Return True if a source marker appears in the function body."""
        defs = self._line_to_func.get(path, [])
        # find start line for func_name
        start_line = None
        end_line = None
        for i, (ln, name) in enumerate(defs):
            if name == func_name:
                start_line = ln
                end_line = defs[i + 1][0] if i + 1 < len(defs) else len(text.splitlines())
                break
        if start_line is None:
            return any(p.search(text) for p in _SOURCE_PATTERNS)
        func_body = "\n".join(text.splitlines()[start_line - 1: end_line])
        return any(p.search(func_body) for p in _SOURCE_PATTERNS)

    def build(self, ctx: SourceContext):
        """Build the call graph from all TypeScript/JavaScript files in ctx."""
        ts_files = ctx.files_by_lang("typescript") + ctx.files_by_lang("javascript")

        for path in ts_files:
            text = ctx.read(path)
            if not text:
                continue

            # Extract function definitions
            raw_defs = self._extract_func_defs(path, text)
            self._line_to_func[path] = raw_defs

            is_route = self._is_route_file(path)
            file_has_default_export = bool(_DEFAULT_EXPORT.search(text))

            for line_no, func_name in raw_defs:
                fd = FuncDef(
                    name=func_name,
                    file=path,
                    line=line_no,
                    is_route=is_route and (file_has_default_export or func_name in ("handler", "default")),
                )
                self.func_defs.setdefault(func_name, []).append(fd)

            # Extract call sites within each function's body
            lines = text.splitlines()
            for i, (line_no, func_name) in enumerate(raw_defs):
                next_start = raw_defs[i + 1][0] if i + 1 < len(raw_defs) else len(lines)
                body = "\n".join(lines[line_no - 1: next_start])

                callee_names: set[str] = set()
                for m in _CALL_SITE.finditer(body):
                    callee_names.add(m.group(1))

                self.callees[(path, func_name)] = callee_names

                # Build inverted index
                for callee in callee_names:
                    self.callers_of.setdefault(callee, []).append((path, func_name))

    def get_func_def(self, func_name: str) -> list[FuncDef]:
        return self.func_defs.get(func_name, [])

    def get_callers(self, func_name: str) -> list[tuple[Path, str]]:
        return self.callers_of.get(func_name, [])

    def func_at_line(self, path: Path, line: int) -> Optional[str]:
        return self._func_at_line(path, line)


# ── taint tracker ─────────────────────────────────────────────────────────────

class SourceTaintTracker:
    """
    Inter-procedural backward slicer: traces from dangerous sinks back to
    HTTP route handlers (trust boundaries).

    Build once, query many times. Call build() before trace_to_source() or trace_all().
    """

    def __init__(self, ctx: SourceContext):
        self.ctx = ctx
        self.cg = CallGraph()
        self._built = False
        self._file_text_cache: dict[Path, str] = {}

    @classmethod
    def from_context(cls, ctx: SourceContext) -> "SourceTaintTracker":
        return cls(ctx)

    def _text(self, path: Path) -> str:
        if path not in self._file_text_cache:
            self._file_text_cache[path] = self.ctx.read(path)
        return self._file_text_cache[path]

    def build(self):
        """Build the call graph. Must be called before tracing."""
        self.cg.build(self.ctx)
        self._built = True

    def _is_route_func(self, path: Path, func_name: str) -> bool:
        """Return True if this function is a route handler (trust boundary)."""
        if not any(p.search(str(path).replace("\\", "/")) for p in _ROUTE_PATH_PATTERNS):
            return False
        text = self._text(path)
        # Route file + function named handler / default export / HTTP verb
        return (
            func_name in ("handler", "default", "GET", "POST", "PUT", "DELETE", "PATCH")
            or bool(_DEFAULT_EXPORT.search(text))
            or any(p.search(text) for p in _ROUTE_MARKERS)
        )

    def _hop_has_source(self, path: Path, func_name: str) -> bool:
        text = self._text(path)
        return self.cg._file_has_source(path, func_name, text)

    def trace_to_source(
        self,
        sink_file: Path,
        sink_line: int,
    ) -> list[TaintPath]:
        """
        Backward-slice from the sink at (sink_file, sink_line).

        Returns all TaintPath objects found (one per unique route handler reached).
        Returns empty list if no route handler is reachable within _MAX_HOP_DEPTH.
        """
        if not self._built:
            self.build()

        # Find the function containing the sink line
        sink_func = self.cg.func_at_line(sink_file, sink_line)
        if sink_func is None:
            # Sink is at module level; treat the file as the route handler
            sink_func = "__module__"

        # BFS backward through the call graph
        # State: (func_name, file, path_so_far)
        start_hop = TaintHop(
            func_name=sink_func,
            file=sink_file,
            line=sink_line,
            rel_path=self.ctx.rel(sink_file),
        )
        # Queue: list of (current_func_name, current_file, list_of_hops)
        queue: deque = deque()
        queue.append((sink_func, sink_file, [start_hop]))
        visited: set[tuple[Path, str]] = {(sink_file, sink_func)}

        results: list[TaintPath] = []

        while queue:
            curr_func, curr_file, path_so_far = queue.popleft()

            if len(path_so_far) > _MAX_HOP_DEPTH:
                continue

            # Check if this is a route handler (trust boundary reached)
            if self._is_route_func(curr_file, curr_func) and len(path_so_far) > 1:
                hops = list(reversed(path_so_far))
                depth = len(hops) - 1  # hops include sink; depth is intermediate hops
                confidence = _confidence_from_depth(depth - 1)
                has_source = any(self._hop_has_source(h.file, h.func_name) for h in hops)
                # Build a dummy sink hit reference from the path's leaf
                sink_hop = path_so_far[0]
                results.append(TaintPath(
                    sink=_make_sink_ref(sink_hop),
                    hops=hops,
                    confidence=confidence,
                    has_source=has_source,
                ))
                continue

            # Walk backward to callers
            callers = self.cg.get_callers(curr_func)
            if not callers:
                # Try callers by file-local function name search
                callers = self._find_callers_by_grep(curr_func, curr_file)

            caller_count = 0
            for caller_file, caller_func in callers:
                if caller_count >= _MAX_CALLERS_PER_FUNC:
                    break
                key = (caller_file, caller_func)
                if key in visited:
                    continue
                visited.add(key)
                caller_line = self._func_start_line(caller_file, caller_func)
                hop = TaintHop(
                    func_name=caller_func,
                    file=caller_file,
                    line=caller_line,
                    rel_path=self.ctx.rel(caller_file),
                )
                queue.append((caller_func, caller_file, [hop] + path_so_far))
                caller_count += 1

        return results

    def _find_callers_by_grep(
        self,
        func_name: str,
        hint_file: Path,
    ) -> list[tuple[Path, str]]:
        """
        Fallback: grep for calls to func_name across TS/JS files.
        Returns (file, containing_func) pairs.
        """
        pattern = re.compile(rf"\b{re.escape(func_name)}\s*\(")
        results: list[tuple[Path, str]] = []
        files = self.ctx.files_by_lang("typescript") + self.ctx.files_by_lang("javascript")

        for f in files:
            text = self.ctx.read(f)
            for m in pattern.finditer(text):
                line_no = text.count("\n", 0, m.start()) + 1
                containing = self.cg.func_at_line(f, line_no)
                if containing and containing != func_name:
                    results.append((f, containing))
        return results[:_MAX_CALLERS_PER_FUNC]

    def _func_start_line(self, path: Path, func_name: str) -> int:
        defs = self.cg._line_to_func.get(path, [])
        for line_no, name in defs:
            if name == func_name:
                return line_no
        return 0

    def trace_all(self, sink_hits: list[SinkHit]) -> list[TaintPath]:
        """
        Trace all sinks from the scanner, returning all found TaintPaths.
        Automatically builds the call graph if not already built.
        """
        if not self._built:
            self.build()
        all_paths: list[TaintPath] = []
        for hit in sink_hits:
            paths = self.trace_to_source(hit.path, hit.line)
            for p in paths:
                # Attach real sink data
                p.sink = hit
            all_paths.extend(paths)
        _conf_rank = {"DIRECT": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        all_paths.sort(key=lambda p: (_conf_rank.get(p.confidence, 4), p.sink.rel_path))
        return all_paths

    @staticmethod
    def report(paths: list[TaintPath], ctx: Optional[SourceContext] = None) -> str:
        if not paths:
            return "No taint paths found."

        lines = ["Taint Paths", "=" * 70]
        counts: dict[str, int] = {}
        for p in paths:
            counts[p.confidence] = counts.get(p.confidence, 0) + 1
        for conf in ["DIRECT", "HIGH", "MEDIUM", "LOW"]:
            n = counts.get(conf, 0)
            if n:
                lines.append(f"  {conf:<8} {n}")
        lines.append("")

        for p in paths:
            src_tag = " [has-source-marker]" if p.has_source else ""
            lines.append(f"── {p.confidence}{src_tag}")
            lines.append(f"   Sink  : [{p.sink.severity}] {p.sink.cwe}  {p.sink.description}")
            lines.append(f"          {p.sink.rel_path}:{p.sink.line}")
            lines.append(f"   Path  :")
            for i, hop in enumerate(p.hops):
                prefix = "  route >" if i == 0 else "        >"
                lines.append(f"   {prefix} {hop.func_name}()  {hop.rel_path}:{hop.line}")
            lines.append("")

        return "\n".join(lines)


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_sink_ref(hop: TaintHop) -> SinkHit:
    """Create a minimal SinkHit reference from a TaintHop for path storage."""
    from ablation.analyzers.source_sink_scanner import SinkHit
    return SinkHit(
        path=hop.file,
        rel_path=hop.rel_path,
        line=hop.line,
        line_text="",
        category="unknown",
        cwe="",
        severity="",
        base_severity="",
        description="",
        guarded=False,
    )


# ── CLI ───────────────────────────────────────────────────────────────────────

def _cli():
    import argparse
    ap = argparse.ArgumentParser(
        prog="source_taint_tracker",
        description="Trace taint paths from route handlers to dangerous sinks",
    )
    ap.add_argument("path", help="Repo path")
    ap.add_argument("--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    default="HIGH", help="Minimum sink severity to trace (default: HIGH)")
    ap.add_argument("--confidence", choices=["DIRECT", "HIGH", "MEDIUM", "LOW"],
                    help="Filter output to one confidence level")
    ap.add_argument("--build-only", action="store_true",
                    help="Build call graph and report stats only")
    args = ap.parse_args()

    print(f"Building SourceContext for {args.path} ...")
    ctx = SourceContext.from_path(args.path)
    print(ctx.summary())

    print("\nBuilding call graph ...")
    tracker = SourceTaintTracker.from_context(ctx)
    tracker.build()

    cg = tracker.cg
    total_funcs = sum(len(v) for v in cg.func_defs.values())
    total_edges = sum(len(v) for v in cg.callees.values())
    print(f"  Functions  : {total_funcs}")
    print(f"  Call edges : {total_edges}")
    print(f"  Unique names: {len(cg.func_defs)}")

    if args.build_only:
        return

    print("\nRunning sink scanner ...")
    scanner = SourceSinkScanner.from_context(ctx)
    _sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    min_rank = _sev_rank.get(args.severity, 1)
    sinks = [h for h in scanner.scan() if _sev_rank.get(h.severity, 5) <= min_rank]
    print(f"  Tracing {len(sinks)} sink(s) ...")

    paths = tracker.trace_all(sinks)

    if args.confidence:
        paths = [p for p in paths if p.confidence == args.confidence]

    print()
    print(tracker.report(paths, ctx))


if __name__ == "__main__":
    _cli()
