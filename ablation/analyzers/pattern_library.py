"""
pattern_library.py: Persistent registry of successful semantic search patterns.

Accumulates query strings that have confirmed RE findings, with hit rates per binary.
Auto-replays all confirmed patterns on new binaries via sweep().

Storage: ~/.ablation/patterns.json

Usage:
    pl = PatternLibrary()
    pl.list()  # show all patterns with hit rates

    # Sweep all patterns against a SemanticSearcher instance:
    results = pl.sweep(searcher, top_k=5)
    for pattern, hits in results.items():
        print(f"{pattern}: {len(hits)} hits")

    # Record a confirmed finding:
    pl.record_hit('strcpy with user-controlled src', binary='libdata.so', va=0x5000, confirmed=True)
    pl.save()

    # Add new pattern:
    pl.add('CLI handler passes argv directly to exec without sanitization',
           tag='cmd-exec')
    pl.save()
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_STORE_DIR = Path.home() / ".ablation"
_STORE_PATH = _STORE_DIR / "patterns.json"

# Increment when new default patterns are added. On load, if the stored
# schema_version is older, new defaults are merged without losing confirmed hits.
_SCHEMA_VERSION = 2

# Default patterns seeded on first load.
# These cover the most common firmware vuln classes and have been validated on FMG 8.0.0.
_DEFAULT_PATTERNS = [
    {
        "query": "strcpy or strcat called with source from user-controlled config string, no length check",
        "tag": "buffer-overflow",
    },
    {
        "query": "sprintf or vsprintf called with format string from user-controlled input",
        "tag": "buffer-overflow",
    },
    {
        "query": "system or popen called with command string constructed from network input",
        "tag": "cmd-exec",
    },
    {
        "query": "Tcl_Eval called with script constructed from user-supplied config or CLI argument",
        "tag": "tcl-inject",
    },
    {
        "query": "exec or execve called with argv from user-controlled input without sanitization",
        "tag": "cmd-exec",
    },
    {
        "query": "CLI handler function passes entry argument directly to shell or exec function",
        "tag": "cmd-exec",
    },
    {
        "query": "user-controlled path joined or concatenated without realpath or traversal check",
        "tag": "path-traversal",
    },
    {
        "query": "config file field parsed into fixed-size stack buffer with no bounds check",
        "tag": "buffer-overflow",
    },
    {
        "query": "password or secret compared with strcmp instead of constant-time function",
        "tag": "timing-side-channel",
    },
    {
        "query": "unchecked length from network packet used in malloc or alloca size calculation",
        "tag": "heap-overflow",
    },
    {
        "query": "CLI command string constructed from user input and evaluated without sanitization",
        "tag": "cmd-inject",
    },
    {
        "query": "function registers CLI tree node with exec callback that receives argv directly",
        "tag": "cmd-exec",
    },
    # Integer overflow / truncation
    {
        "query": "arithmetic on user-controlled size or count value used as allocation argument, possible integer overflow or wrap",
        "tag": "integer-overflow",
    },
    {
        "query": "multiplication of user-supplied count and element-size passed to malloc without overflow check",
        "tag": "integer-overflow",
    },
    # Use-after-free / double-free
    {
        "query": "pointer freed inside loop or error path then dereferenced or freed again in cleanup",
        "tag": "use-after-free",
    },
    {
        "query": "object reference passed to free then referenced again in subsequent callback or signal handler",
        "tag": "use-after-free",
    },
    {
        "query": "heap pointer freed twice on error unwind with no NULL assignment between frees",
        "tag": "double-free",
    },
    # Format string
    {
        "query": "printf or syslog called with user-controlled argument directly in format position",
        "tag": "format-string",
    },
    {
        "query": "log or debug function constructs format string from user-supplied message field",
        "tag": "format-string",
    },
    # Race conditions
    {
        "query": "shared counter or flag read and written from multiple threads without mutex protection",
        "tag": "race-condition",
    },
    {
        "query": "check-then-use pattern on file or socket descriptor across a non-atomic operation",
        "tag": "race-condition",
    },
    # DoS / resource exhaustion
    {
        "query": "loop iterates until packet field reaches zero, no iteration bound, possible infinite loop",
        "tag": "dos",
    },
    {
        "query": "memory allocation inside parsing loop driven by attacker-controlled count field, no upper bound",
        "tag": "dos",
    },
    # Info leak
    {
        "query": "stack buffer or heap object returned in response without zeroing uninitialized bytes",
        "tag": "info-leak",
    },
    {
        "query": "error response includes pointer value, kernel address, or internal struct field",
        "tag": "info-leak",
    },
    # Auth bypass
    {
        "query": "authentication check returns success when underlying function returns error code",
        "tag": "auth-bypass",
    },
    {
        "query": "session token or credential comparison short-circuits on empty or null input",
        "tag": "auth-bypass",
    },
    # Crypto misuse
    {
        "query": "IV or nonce reused across encryption calls, or nonce derived from predictable counter",
        "tag": "crypto",
    },
    {
        "query": "SSL or TLS certificate verification disabled or return value from verify callback ignored",
        "tag": "crypto",
    },
]


@dataclass
class PatternHit:
    binary: str
    va: int
    score: float
    confirmed: bool = False
    timestamp: float = field(default_factory=time.time)


@dataclass
class Pattern:
    query: str
    tag: str = ""
    hits: List[PatternHit] = field(default_factory=list)
    created: float = field(default_factory=time.time)

    @property
    def confirmed_hit_count(self) -> int:
        return sum(1 for h in self.hits if h.confirmed)

    @property
    def total_hit_count(self) -> int:
        return len(self.hits)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "query": self.query,
            "tag": self.tag,
            "hits": [asdict(h) for h in self.hits],
            "created": self.created,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Pattern":
        hits = [PatternHit(**h) for h in d.get("hits", [])]
        return cls(
            query=d["query"],
            tag=d.get("tag", ""),
            hits=hits,
            created=d.get("created", 0.0),
        )


@dataclass
class SweepResult:
    pattern: str
    tag: str
    hits: List[Tuple[int, float]]  # (va, score)


class PatternLibrary:
    """
    Persistent registry of semantic search patterns with hit tracking.

    Backed by ~/.ablation/patterns.json. First instantiation seeds default patterns.
    """

    def __init__(self, store_path: Optional[str] = None):
        self._path = Path(store_path) if store_path else _STORE_PATH
        self._patterns: List[Pattern] = []
        self._load()

    # ── load / save ──────────────────────────────────────────────────────────

    def _load(self) -> None:
        _STORE_DIR.mkdir(parents=True, exist_ok=True)
        stored_version = 0
        if self._path.exists():
            try:
                data = json.loads(self._path.read_text())
                self._patterns = [Pattern.from_dict(p) for p in data.get("patterns", [])]
                stored_version = data.get("schema_version", 0)
            except (json.JSONDecodeError, KeyError):
                self._patterns = []
        if not self._patterns:
            self._seed_defaults()
        elif stored_version < _SCHEMA_VERSION:
            self._merge_new_defaults()

    def save(self) -> None:
        _STORE_DIR.mkdir(parents=True, exist_ok=True)
        data = {"schema_version": _SCHEMA_VERSION, "patterns": [p.to_dict() for p in self._patterns]}
        self._path.write_text(json.dumps(data, indent=2))

    def _seed_defaults(self) -> None:
        for d in _DEFAULT_PATTERNS:
            self._patterns.append(Pattern(query=d["query"], tag=d["tag"]))

    def _merge_new_defaults(self) -> None:
        existing = {p.query for p in self._patterns}
        added = 0
        for d in _DEFAULT_PATTERNS:
            if d["query"] not in existing:
                self._patterns.append(Pattern(query=d["query"], tag=d["tag"]))
                added += 1
        if added:
            self.save()
        self.save()

    # ── management ───────────────────────────────────────────────────────────

    def add(self, query: str, tag: str = "") -> Pattern:
        """Add a new pattern. Returns the Pattern object."""
        for p in self._patterns:
            if p.query == query:
                return p  # already exists
        p = Pattern(query=query, tag=tag)
        self._patterns.append(p)
        return p

    def remove(self, query: str) -> bool:
        """Remove pattern by exact query string. Returns True if found."""
        before = len(self._patterns)
        self._patterns = [p for p in self._patterns if p.query != query]
        return len(self._patterns) < before

    def get(self, query: str) -> Optional[Pattern]:
        for p in self._patterns:
            if p.query == query:
                return p
        return None

    def list(self, tag: Optional[str] = None) -> str:
        """Return formatted table of patterns with hit stats."""
        patterns = self._patterns
        if tag:
            patterns = [p for p in patterns if p.tag == tag]
        lines = [
            f"PatternLibrary: {len(patterns)} patterns  ({self._path})",
            f"  {'Tag':<20} {'Confirmed':>9} {'Total':>6}  Query",
            f"  {'-'*20} {'--------':>9} {'-----':>6}  -----",
        ]
        for p in sorted(patterns, key=lambda x: -x.confirmed_hit_count):
            tag_col = (p.tag or "")[:20]
            lines.append(
                f"  {tag_col:<20} {p.confirmed_hit_count:>9} {p.total_hit_count:>6}  {p.query[:70]}"
            )
        return "\n".join(lines)

    # ── hit recording ─────────────────────────────────────────────────────────

    def record_hit(
        self,
        query: str,
        binary: str,
        va: int,
        score: float = 1.0,
        confirmed: bool = False,
    ) -> None:
        """Record that a pattern matched a function VA in a binary."""
        p = self.get(query)
        if p is None:
            p = self.add(query)
        # Avoid duplicate recording for same binary+va
        for h in p.hits:
            if h.binary == binary and h.va == va:
                if confirmed and not h.confirmed:
                    h.confirmed = True
                return
        p.hits.append(PatternHit(binary=binary, va=va, score=score, confirmed=confirmed))

    # ── sweep ─────────────────────────────────────────────────────────────────

    def sweep(
        self,
        searcher,
        top_k: int = 5,
        min_score: float = 0.3,
        tags: Optional[List[str]] = None,
    ) -> Dict[str, SweepResult]:
        """
        Run all patterns against a SemanticSearcher instance.

        searcher: a SemanticSearcher with corpus already built (searcher.build_corpus())
        top_k:    max results per pattern
        min_score: minimum similarity threshold
        tags:     if set, only run patterns matching these tags

        Returns: {query: SweepResult}
        """
        results: Dict[str, SweepResult] = {}
        patterns = self._patterns
        if tags:
            patterns = [p for p in patterns if p.tag in tags]

        for p in patterns:
            try:
                hits = searcher.query(p.query, top_k=top_k)
            except Exception:
                continue
            hits = [h for h in hits if h.score >= min_score]
            results[p.query] = SweepResult(
                pattern=p.query,
                tag=p.tag,
                hits=[(h.va, h.score) for h in hits],
            )

        return results

    def fmt_sweep(
        self,
        results: Dict[str, SweepResult],
        binary_name: str = "",
    ) -> str:
        """Format sweep results as a compact report."""
        lines = [f"PatternLibrary sweep{': ' + binary_name if binary_name else ''}"]
        for query, r in results.items():
            if not r.hits:
                continue
            lines.append(f"\n  [{r.tag}] {query[:70]}")
            for va, score in r.hits[:5]:
                lines.append(f"    0x{va:x}  score={score:.3f}")
        if not any(r.hits for r in results.values()):
            lines.append("  (no hits above threshold)")
        return "\n".join(lines)
