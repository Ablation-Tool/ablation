"""
source_ingestion.py: repo ingestion and context building for source RE.

Builds a lightweight SourceContext index over a local or remote git repo.
SourceContext is the source analog of BinaryContext: a fast, cached surface
that all downstream source analyzers consume without re-scanning the tree.

Usage:
    from ablation.analyzers.source_ingestion import SourceContext

    # From an existing local clone
    ctx = SourceContext.from_path("/tmp/langfuse")
    print(ctx.summary())

    # Clone from remote (shallow)
    ctx = SourceContext.from_git("https://github.com/langfuse/langfuse", "/tmp/langfuse")
    print(ctx.summary())

    # Access indexed surfaces
    for f in ctx.route_files:
        print(f.relative_to(ctx.repo_root))

CLI:
    python3 -m ablation.analyzers.source_ingestion /tmp/langfuse
    python3 -m ablation.analyzers.source_ingestion --clone https://github.com/langfuse/langfuse /tmp/langfuse
"""

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Optional

# Extensions treated as source files per language
_LANG_EXTS: dict[str, str] = {
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".py": "python",
    ".rs": "rust",
    ".go": "go",
    ".java": "java",
    ".rb": "ruby",
    ".php": "php",
}

# Directories that are never source (always skip)
_SKIP_DIRS = frozenset([
    "node_modules", ".git", ".next", "__pycache__", ".cache",
    "dist", "build", ".turbo", "coverage", ".nyc_output",
    "target",  # Rust build output
])

# Patterns that identify HTTP route files per framework
_ROUTE_PATTERNS: list[tuple[str, re.Pattern]] = [
    # Next.js pages router
    ("nextjs-pages", re.compile(r"pages[/\\]api[/\\].*\.(ts|js)$")),
    # Next.js app router
    ("nextjs-app", re.compile(r"app[/\\].*route\.(ts|js)$")),
    # Express / Fastify routers
    ("express", re.compile(r"\.(ts|js)$")),
    # Python ASGI/WSGI
    ("python-web", re.compile(r"\.py$")),
    # Axum / Actix / Rocket
    ("rust-web", re.compile(r"\.rs$")),
]

# Content patterns that confirm a file is an HTTP route handler
_ROUTE_CONTENT_SIGNALS: list[re.Pattern] = [
    # Next.js
    re.compile(r"\bexport\s+default\s+(async\s+)?function\s+(handler|default)\b"),
    re.compile(r"\bexport\s+\{\s*GET\b|\bexport\s+\{\s*POST\b"),
    re.compile(r"\bexport\s+const\s+(GET|POST|PUT|DELETE|PATCH)\s*="),
    # Express / Fastify
    re.compile(r"\b(app|router)\.(get|post|put|delete|patch|use)\s*\("),
    # Python Flask / FastAPI / Django
    re.compile(r"@(app|router|bp)\.(get|post|put|delete|patch|route)\s*\("),
    re.compile(r"@api_view\s*\("),
    # Axum / Actix
    re.compile(r"#\[(get|post|put|delete|patch)\("),
]


def _is_route_file(path: Path) -> bool:
    """Return True if file content looks like an HTTP route handler."""
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    return any(p.search(text) for p in _ROUTE_CONTENT_SIGNALS)


def _walk_source_files(root: Path) -> list[Path]:
    """Recursively collect source files, skipping build/vendor dirs."""
    out: list[Path] = []
    for p in root.rglob("*"):
        if p.is_dir():
            continue
        if any(skip in p.parts for skip in _SKIP_DIRS):
            continue
        if p.suffix.lower() in _LANG_EXTS:
            out.append(p)
    return out


def _detect_package_roots(root: Path) -> list[Path]:
    """Find monorepo workspace roots (directories with a package.json)."""
    roots: list[Path] = []
    for pkg in root.rglob("package.json"):
        if any(skip in pkg.parts for skip in _SKIP_DIRS):
            continue
        roots.append(pkg.parent)
    return sorted(roots)


class SourceContext:
    """
    Lightweight index of a source repository for use by source RE analyzers.

    Attributes:
        repo_root     : root directory of the repository
        all_files     : all source files (filtered by language extension)
        route_files   : files identified as HTTP route handlers
        lang_map      : {language_name: [Path, ...]}
        package_roots : monorepo workspace roots (directories with package.json)
    """

    def __init__(
        self,
        repo_root: Path,
        all_files: list[Path],
        route_files: list[Path],
        lang_map: dict[str, list[Path]],
        package_roots: list[Path],
    ):
        self.repo_root = repo_root
        self.all_files = all_files
        self.route_files = route_files
        self.lang_map = lang_map
        self.package_roots = package_roots

    # ── constructors ─────────────────────────────────────────────────────────

    @classmethod
    def from_path(cls, path: str | Path) -> "SourceContext":
        """Build a SourceContext from an existing local repository."""
        root = Path(path).resolve()
        if not root.is_dir():
            raise ValueError(f"Not a directory: {root}")

        all_files = _walk_source_files(root)
        lang_map: dict[str, list[Path]] = {}
        for f in all_files:
            lang = _LANG_EXTS.get(f.suffix.lower(), "unknown")
            lang_map.setdefault(lang, []).append(f)

        route_files = [f for f in all_files if _is_route_file(f)]
        package_roots = _detect_package_roots(root)

        return cls(root, all_files, route_files, lang_map, package_roots)

    @classmethod
    def from_git(cls, url: str, dest: str | Path, depth: int = 1) -> "SourceContext":
        """Shallow-clone a repository and return a SourceContext."""
        dest = Path(dest)
        if dest.exists():
            raise FileExistsError(f"Destination already exists: {dest}. Remove it or use from_path().")
        result = subprocess.run(
            ["git", "clone", f"--depth={depth}", url, str(dest)],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"git clone failed:\n{result.stderr.strip()}")
        return cls.from_path(dest)

    # ── queries ───────────────────────────────────────────────────────────────

    def read(self, path: Path) -> str:
        """Return file contents, empty string on error."""
        try:
            return path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return ""

    def rel(self, path: Path) -> str:
        """Return path relative to repo_root as a string."""
        try:
            return str(path.relative_to(self.repo_root))
        except ValueError:
            return str(path)

    def files_by_lang(self, lang: str) -> list[Path]:
        """Return all source files for a given language name."""
        return self.lang_map.get(lang, [])

    def grep(self, pattern: str | re.Pattern, lang: Optional[str] = None) -> list[tuple[Path, int, str]]:
        """
        Grep all source files (or a specific language) for a regex pattern.

        Returns list of (path, line_number, line_text) tuples.
        """
        if isinstance(pattern, str):
            pattern = re.compile(pattern)
        files = self.files_by_lang(lang) if lang else self.all_files
        hits: list[tuple[Path, int, str]] = []
        for f in files:
            text = self.read(f)
            for i, line in enumerate(text.splitlines(), 1):
                if pattern.search(line):
                    hits.append((f, i, line.rstrip()))
        return hits

    def grep_context(
        self,
        pattern: str | re.Pattern,
        context_lines: int = 3,
        lang: Optional[str] = None,
    ) -> list[dict]:
        """
        Like grep() but returns surrounding context lines.

        Each result: {path, line, match_line, context_before, context_after}
        """
        if isinstance(pattern, str):
            pattern = re.compile(pattern)
        files = self.files_by_lang(lang) if lang else self.all_files
        results: list[dict] = []
        for f in files:
            lines = self.read(f).splitlines()
            for i, line in enumerate(lines):
                if pattern.search(line):
                    before = lines[max(0, i - context_lines): i]
                    after = lines[i + 1: i + 1 + context_lines]
                    results.append({
                        "path": f,
                        "line": i + 1,
                        "match_line": line.rstrip(),
                        "context_before": before,
                        "context_after": after,
                    })
        return results

    # ── summary ───────────────────────────────────────────────────────────────

    def summary(self) -> str:
        lines = [
            f"SourceContext: {self.repo_root}",
            f"  Total source files : {len(self.all_files)}",
            f"  Route files        : {len(self.route_files)}",
            f"  Package workspaces : {len(self.package_roots)}",
            "  Languages:",
        ]
        for lang, files in sorted(self.lang_map.items(), key=lambda x: -len(x[1])):
            lines.append(f"    {lang:<15} {len(files):>4} files")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "repo_root": str(self.repo_root),
            "total_files": len(self.all_files),
            "route_files": len(self.route_files),
            "package_roots": [str(p.relative_to(self.repo_root)) for p in self.package_roots],
            "lang_counts": {k: len(v) for k, v in self.lang_map.items()},
        }


# ── CLI ───────────────────────────────────────────────────────────────────────

def _cli():
    import argparse
    ap = argparse.ArgumentParser(prog="source_ingestion", description="Build SourceContext for a repo")
    ap.add_argument("path", nargs="?", help="Local repo path")
    ap.add_argument("--clone", metavar="URL", help="Clone URL (dest=path)")
    ap.add_argument("--json", action="store_true", help="Output JSON summary")
    args = ap.parse_args()

    if args.clone:
        if not args.path:
            ap.error("--clone requires a destination path argument")
        ctx = SourceContext.from_git(args.clone, args.path)
    elif args.path:
        ctx = SourceContext.from_path(args.path)
    else:
        ap.print_help()
        sys.exit(1)

    if args.json:
        print(json.dumps(ctx.to_dict(), indent=2))
    else:
        print(ctx.summary())
        print("\nRoute files:")
        for f in ctx.route_files[:30]:
            print(f"  {ctx.rel(f)}")
        if len(ctx.route_files) > 30:
            print(f"  ... {len(ctx.route_files) - 30} more")


if __name__ == "__main__":
    _cli()
