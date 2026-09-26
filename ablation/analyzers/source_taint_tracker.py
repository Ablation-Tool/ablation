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

Architecture: lazy grep-per-function
  build()           — scans all TS/JS files for function definition locations
                      (name + line number). Fast and low-memory: no call sites stored.
  _get_callers(fn)  — called during BFS; greps repo for files containing fn(),
                      then parses only those files for the containing function.
                      Results cached — each unique function name is grepped once.

  This means we grep for ~20-50 unique function names (the functions actually
  on the backward path for 3 sinks at depth 6), not all functions in 5237 files.
  Contrast with an eager full call graph which OOMs at 5k+ TS files.

Trust boundary: any file under pages/api/ or app/api/ that exports a default
handler function. These files receive HTTP requests (req.body, req.query, etc.)
and are the source of all user-controlled data in Next.js applications.

Confidence levels:
  DIRECT  : sink is inside a route handler (0 hops)
  HIGH    : route handler → 1 intermediate → sink
  MEDIUM  : route handler → 2 intermediates → sink
  LOW     : route handler → 3+ intermediates → sink (some regex FP risk)

Usage:
    from ablation.analyzers.source_ingestion import SourceContext
    from ablation.analyzers.source_sink_scanner import SourceSinkScanner, SinkHit
    from ablation.analyzers.source_taint_tracker import SourceTaintTracker

    ctx = SourceContext.from_path("/tmp/langfuse")
    tracker = SourceTaintTracker.from_context(ctx)
    tracker.build()

    scanner = SourceSinkScanner.from_context(ctx)
    sinks = [h for h in scanner.scan() if h.severity in ("CRITICAL", "HIGH")]
    paths = tracker.trace_all(sinks)
    print(tracker.report(paths))

CLI:
    python3 -m ablation.analyzers.source_taint_tracker /tmp/langfuse
    python3 -m ablation.analyzers.source_taint_tracker /tmp/langfuse --severity HIGH
"""

import re
import subprocess
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

# ── regex patterns ────────────────────────────────────────────────────────────

_FUNC_DECL = re.compile(
    r"^[ \t]*(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*[(<]",
    re.MULTILINE,
)
_FUNC_ASSIGN = re.compile(
    r"^[ \t]*(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:\([^)]*\)|[a-zA-Z_]\w*)\s*=>",
    re.MULTILINE,
)
_CLASS_METHOD = re.compile(
    r"^[ \t]{2,}(?:(?:public|private|protected|static|async|override)\s+)*(\w+)\s*\([^)]*\)\s*(?::\s*[\w<>\[\]|&, ]+\s*)?\{",
    re.MULTILINE,
)
_DEFAULT_EXPORT = re.compile(
    r"^(?:export\s+default\s+(?:async\s+)?function\s*(?:\w+)?\s*\(|export\s+default\s+handler)",
    re.MULTILINE,
)

_SOURCE_PATTERNS: list[re.Pattern] = [
    re.compile(r"\breq\.(body|query|params|headers)\b"),
    re.compile(r"\brequest\.(body|json|form|args|query_params)\b"),
    re.compile(r"\breadJsonBody\b"),
    re.compile(r"\bJSON\.parse\("),
]

_ROUTE_MARKERS: list[re.Pattern] = [
    re.compile(r"export\s+default\s+(?:async\s+)?function"),
    re.compile(r"export\s+const\s+(?:GET|POST|PUT|DELETE|PATCH)\s*="),
    re.compile(r"export\s+default\s+(?:async\s+)?handler"),
    re.compile(r"router\.(get|post|put|delete|patch)\s*\("),
    re.compile(r"app\.(get|post|put|delete|patch)\s*\("),
]

_ROUTE_PATH_PATTERNS: list[re.Pattern] = [
    re.compile(r"pages[/\\]api[/\\]"),
    re.compile(r"app[/\\]api[/\\].*route\.(ts|js)$"),
    re.compile(r"routes?[/\\].*\.(ts|js)$"),
    re.compile(r"controllers?[/\\].*\.(ts|js)$"),
    re.compile(r"worker[/\\]src[/\\]app\.(ts|js)$"),
    # Worker queue processors — trust boundary for async job input (equiv. of req.body)
    re.compile(r"worker[/\\]src[/\\]queues?[/\\].*\.(ts|js)$"),
    re.compile(r"worker[/\\]src[/\\].*[Qq]ueue.*\.(ts|js)$"),
]

# Worker job processor function name patterns — additional trust boundary signal
_WORKER_ENTRY_PATTERNS: list[re.Pattern] = [
    re.compile(r"\bprocess\w*Eval\b"),
    re.compile(r"\bprocess\w*Job\b"),
    re.compile(r"\bhandle\w*Job\b"),
    re.compile(r"\bQueueProcessorBuilder\b"),
    re.compile(r"new\s+Worker\s*\("),
    re.compile(r"\.process\s*\("),   # BullMQ worker.process(...)
]

_SKIP_FUNC_NAMES = frozenset([
    "if", "else", "for", "while", "switch", "return", "const", "let", "var",
    "type", "interface", "class", "enum", "import", "export", "from", "async",
    "await", "new", "delete", "typeof", "instanceof",
])

_MAX_HOP_DEPTH = 6
_MAX_CALLERS_PER_FUNC = 30

# Method names so common they produce cross-layer FPs. When a caller of one of
# these names lives in a UI component/hook/store file and the sink is in a
# backend/worker package, the connection is a name collision, not a real path.
_OVERLOADED_NAMES = frozenset([
    "dispatch", "send", "execute", "process", "run", "call", "invoke",
    "emit", "trigger", "fire", "publish", "notify", "handle",
    "create", "build", "get", "set", "update", "delete", "fetch",
])

# Path fragments that mark UI-layer files (frontend components, hooks, stores).
# Callers in these paths are excluded when the sink is in a backend/worker module.
_FRONTEND_PATH_FRAGMENTS = frozenset([
    "/components/", "/hooks/", "/stores/", "/context/", "/ui/",
    "/pages/", "/app/", "/views/", "/layouts/", "/widgets/",
])

# Path fragments that mark backend/worker modules.
_BACKEND_PATH_FRAGMENTS = frozenset([
    "/server/", "/worker/", "/queues/", "/services/", "/features/evals/",
    "packages/shared/src/server",
])

# Files that should not appear on production taint paths
_EXEMPT_PATH_FRAGMENTS = frozenset([
    ".test.", ".spec.", "__tests__", ".servertest.", ".clienttest.", ".gatewaye2e.",
    "/test/", "/tests/", "/fixtures/", "/mocks/", "/mock/",
    "seed", "seeder", "/scripts/", "/bin/", "/cli/",
    "backgroundMigrations", "/migration", ".integration.test.",
    ".mjs",  # standalone scripts (code-eval-runners, etc.)
])


# ── data structures ───────────────────────────────────────────────────────────

@dataclass
class TaintHop:
    func_name: str
    file: Path
    line: int
    rel_path: str

    def __str__(self) -> str:
        return f"{self.rel_path}:{self.line}  {self.func_name}()"


@dataclass
class TaintPath:
    sink: SinkHit
    hops: list[TaintHop]    # [route_handler, ..., func_containing_sink]
    confidence: str          # DIRECT | HIGH | MEDIUM | LOW
    has_source: bool

    @property
    def depth(self) -> int:
        return len(self.hops)

    def as_dict(self) -> dict:
        return {
            "sink_file": self.sink.rel_path,
            "sink_line": self.sink.line,
            "confidence": self.confidence,
            "has_source": self.has_source,
            "depth": self.depth,
            "path": [{"func": h.func_name, "file": h.rel_path, "line": h.line} for h in self.hops],
        }


# Keep CallGraph as a lightweight name (for __init__ export compatibility)
class CallGraph:
    """Lightweight stub — actual graph is built lazily inside SourceTaintTracker."""
    pass


def _confidence_from_depth(intermediate_hops: int) -> str:
    if intermediate_hops == 0:
        return "DIRECT"
    if intermediate_hops == 1:
        return "HIGH"
    if intermediate_hops == 2:
        return "MEDIUM"
    return "LOW"


# ── helpers ───────────────────────────────────────────────────────────────────

def _extract_func_defs(text: str) -> list[tuple[int, str]]:
    """Return sorted (line_no, func_name) pairs for all function definitions."""
    defs: list[tuple[int, str]] = []
    for pattern in [_FUNC_DECL, _FUNC_ASSIGN, _CLASS_METHOD]:
        for m in pattern.finditer(text):
            name = m.group(1)
            if name in _SKIP_FUNC_NAMES:
                continue
            line_no = text.count("\n", 0, m.start()) + 1
            defs.append((line_no, name))
    defs.sort()
    # Deduplicate same line
    seen: set[int] = set()
    result = []
    for ln, name in defs:
        if ln not in seen:
            seen.add(ln)
            result.append((ln, name))
    return result


def _func_at_line(defs: list[tuple[int, str]], target_line: int) -> Optional[str]:
    result = None
    for line_no, name in defs:
        if line_no <= target_line:
            result = name
        else:
            break
    return result


def _is_route_file(path: Path) -> bool:
    rel = str(path).replace("\\", "/")
    return any(p.search(rel) for p in _ROUTE_PATH_PATTERNS)


def _is_route_func(path: Path, func_name: str, text: str) -> bool:
    if not _is_route_file(path):
        return False
    if any(p.search(str(path).replace("\\", "/")) for p in _ROUTE_PATH_PATTERNS[-2:]):
        # Worker queue file: accept any exported function or known processor pattern
        return (
            any(p.search(func_name) for p in _WORKER_ENTRY_PATTERNS)
            or bool(re.search(r"\bexport\b.*\b" + re.escape(func_name) + r"\b", text))
        )
    return (
        func_name in ("handler", "default", "GET", "POST", "PUT", "DELETE", "PATCH")
        or bool(_DEFAULT_EXPORT.search(text))
        or any(p.search(text) for p in _ROUTE_MARKERS)
    )


def _has_source_marker(text: str) -> bool:
    return any(p.search(text) for p in _SOURCE_PATTERNS)


# ── taint tracker ─────────────────────────────────────────────────────────────

class SourceTaintTracker:
    """
    Inter-procedural backward slicer: lazy grep-per-function approach.

    build()        : scan all files for function definition locations (fast).
    trace_to_source: BFS backward; each unique function name gets one grep
                     call to find its callers — results cached.
    """

    def __init__(self, ctx: SourceContext):
        self.ctx = ctx
        # file → sorted [(line_no, func_name)]
        self._file_defs: dict[Path, list[tuple[int, str]]] = {}
        # func_name → [(caller_file, caller_func_name)] — populated lazily
        self._callers_cache: dict[str, list[tuple[Path, str]]] = {}
        self._built = False
        self.cg = CallGraph()  # stub for API compatibility

    @classmethod
    def from_context(cls, ctx: SourceContext) -> "SourceTaintTracker":
        return cls(ctx)

    def build(self):
        """
        Phase 1: extract function definition locations from all TS/JS files.
        Does NOT build call sites (that's done lazily per function during BFS).
        """
        files = self.ctx.files_by_lang("typescript") + self.ctx.files_by_lang("javascript")
        for path in files:
            text = self.ctx.read(path)
            if not text:
                continue
            self._file_defs[path] = _extract_func_defs(text)
        self._built = True

    def _grep_files_calling(self, func_name: str) -> list[Path]:
        """
        Return all source files that contain a call to func_name().
        Uses ripgrep if available, else grep -r.
        """
        pattern = rf"\b{re.escape(func_name)}\s*\("
        repo = str(self.ctx.repo_root)

        # Try ripgrep first (much faster on large repos)
        for cmd in [
            ["rg", "--files-with-matches", "-t", "ts", "-t", "js", pattern, repo],
            ["grep", "-r", "-l", "--include=*.ts", "--include=*.js", "-E", pattern, repo],
        ]:
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True, text=True,
                    timeout=15,
                )
                if result.returncode in (0, 1):  # 1 = no matches, still valid
                    paths = [Path(p) for p in result.stdout.strip().splitlines() if p]
                    return paths
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
        return []

    def _get_callers(self, func_name: str) -> list[tuple[Path, str]]:
        """
        Return [(caller_file, caller_func_name)] for all callers of func_name.
        Results cached — each unique function name is grepped once.
        """
        if func_name in self._callers_cache:
            return self._callers_cache[func_name]

        candidates = self._grep_files_calling(func_name)
        call_re = re.compile(rf"\b{re.escape(func_name)}\s*\(")

        results: list[tuple[Path, str]] = []
        seen: set[tuple[Path, str]] = set()

        # For overloaded names, exclude frontend files when the source
        # function name maps to a backend module (layer mismatch = FP).
        is_overloaded = func_name in _OVERLOADED_NAMES

        for path in candidates:
            rel = str(path).replace("\\", "/")
            if any(frag in rel for frag in _EXEMPT_PATH_FRAGMENTS):
                continue
            if is_overloaded and any(frag in rel for frag in _FRONTEND_PATH_FRAGMENTS):
                continue
            text = self.ctx.read(path)
            if not text:
                continue
            defs = self._file_defs.get(path) or _extract_func_defs(text)

            for m in call_re.finditer(text):
                line_no = text.count("\n", 0, m.start()) + 1
                container = _func_at_line(defs, line_no)
                if container and container != func_name:
                    key = (path, container)
                    if key not in seen:
                        seen.add(key)
                        results.append((path, container))

            if len(results) >= _MAX_CALLERS_PER_FUNC:
                results = results[:_MAX_CALLERS_PER_FUNC]
                break

        self._callers_cache[func_name] = results
        return results

    def trace_to_source(self, sink_file: Path, sink_line: int) -> list[TaintPath]:
        """
        Backward-slice from the sink at (sink_file, sink_line).
        Returns TaintPath objects for each distinct route handler reached.
        """
        if not self._built:
            self.build()

        # Find function containing the sink
        defs = self._file_defs.get(sink_file) or []
        sink_func = _func_at_line(defs, sink_line) or "__module__"

        start_hop = TaintHop(
            func_name=sink_func,
            file=sink_file,
            line=sink_line,
            rel_path=self.ctx.rel(sink_file),
        )

        # BFS: (curr_func, curr_file, path_so_far)
        queue: deque = deque([(sink_func, sink_file, [start_hop])])
        visited: set[tuple[Path, str]] = {(sink_file, sink_func)}
        results: list[TaintPath] = []

        while queue:
            curr_func, curr_file, path_so_far = queue.popleft()

            if len(path_so_far) > _MAX_HOP_DEPTH:
                continue

            # Check if this node is a route handler (trust boundary)
            if len(path_so_far) > 1:
                text = self.ctx.read(curr_file)
                if _is_route_func(curr_file, curr_func, text or ""):
                    hops = list(reversed(path_so_far))
                    depth = len(hops) - 1
                    has_source = any(
                        _has_source_marker(self.ctx.read(h.file) or "")
                        for h in hops
                    )
                    results.append(TaintPath(
                        sink=_make_sink_ref(path_so_far[0]),
                        hops=hops,
                        confidence=_confidence_from_depth(depth - 1),
                        has_source=has_source,
                    ))
                    continue

            for caller_file, caller_func in self._get_callers(curr_func):
                key = (caller_file, caller_func)
                if key in visited:
                    continue
                visited.add(key)

                caller_defs = self._file_defs.get(caller_file) or []
                caller_line = next(
                    (ln for ln, nm in caller_defs if nm == caller_func), 0
                )
                hop = TaintHop(
                    func_name=caller_func,
                    file=caller_file,
                    line=caller_line,
                    rel_path=self.ctx.rel(caller_file),
                )
                queue.append((caller_func, caller_file, [hop] + path_so_far))

        return results

    def trace_all(self, sink_hits: list[SinkHit]) -> list[TaintPath]:
        """Trace all sinks, attach real SinkHit objects to paths."""
        if not self._built:
            self.build()

        all_paths: list[TaintPath] = []
        for hit in sink_hits:
            paths = self.trace_to_source(hit.path, hit.line)
            for p in paths:
                p.sink = hit
            all_paths.extend(paths)

        _rank = {"DIRECT": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        all_paths.sort(key=lambda p: (_rank.get(p.confidence, 4), p.sink.rel_path))
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

def _make_sink_ref(hop: TaintHop) -> "SinkHit":
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
                    default="HIGH", help="Minimum sink severity (default: HIGH)")
    ap.add_argument("--confidence", choices=["DIRECT", "HIGH", "MEDIUM", "LOW"],
                    help="Filter output to one confidence level")
    ap.add_argument("--build-only", action="store_true",
                    help="Build func-def index and report stats only")
    args = ap.parse_args()

    import time
    print(f"Building SourceContext for {args.path} ...")
    ctx = SourceContext.from_path(args.path)
    print(ctx.summary())

    t0 = time.time()
    print("\nBuilding function definition index ...")
    tracker = SourceTaintTracker.from_context(ctx)
    tracker.build()
    n_files = len(tracker._file_defs)
    n_funcs = sum(len(v) for v in tracker._file_defs.values())
    print(f"  Files indexed : {n_files}")
    print(f"  Functions     : {n_funcs}")
    print(f"  Build time    : {time.time()-t0:.1f}s")

    if args.build_only:
        return

    print("\nRunning sink scanner ...")
    scanner = SourceSinkScanner.from_context(ctx)
    _sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    min_rank = _sev_rank.get(args.severity, 1)
    sinks = [h for h in scanner.scan() if _sev_rank.get(h.severity, 5) <= min_rank]
    print(f"  Tracing {len(sinks)} sink(s) ...")

    t1 = time.time()
    paths = tracker.trace_all(sinks)
    print(f"  Trace time : {time.time()-t1:.1f}s")
    print(f"  Paths found: {len(paths)}")

    if args.confidence:
        paths = [p for p in paths if p.confidence == args.confidence]

    print()
    print(tracker.report(paths))


if __name__ == "__main__":
    _cli()
