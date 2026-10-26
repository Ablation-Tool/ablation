"""
cgi_surface_mapper.py: map and triage the HTTP CGI attack surface of an embedded Linux firmware rootfs.

Why this exists:
1. IoT firmware ships 50-200 CGI handlers as the entire web attack surface. Manually
   enumerating and classifying each handler takes hours. This module does it in one call.

2. Shell CGI handlers are the highest-value targets (VIVOTEK had 60+ shell CGIs;
   upload_vadp alone had VIVOTEK-001 CONFIRMED HIGH). ShellSinkClassifier can sweep
   all of them in seconds. This module wires that pipeline together.

3. ELF CGI handlers are queued as BinaryContext targets with their path, so the caller
   can immediately run BinaryContext.load_or_build() + SinkArgClassifier on them.

Output: a prioritized CGI surface table:
  - Shell handlers with ARG_PROPAGATED sinks (highest priority)
  - Shell handlers with EVAL_SINK or UNKNOWN sinks
  - ELF handlers (queued for binary RE)
  - Shell handlers with only RODATA_CONST sinks (lowest priority)

Usage::

    from ablation.analyzers.cgi_surface_mapper import CGISurfaceMapper

    mapper = CGISurfaceMapper.from_rootfs('/media/fw/rootfs_mount')
    surface = mapper.map()
    print(mapper.report(surface))

    # Get only handlers with confirmed injection risk:
    risky = [h for h in surface.risky if h.max_verdict != 'UNKNOWN']

    # Get ELF CGI paths for binary RE:
    elf_targets = [h.abs_path for h in surface if h.handler_type == 'elf']

CLI::

    python3 -m ablation.analyzers.cgi_surface_mapper /path/to/rootfs/
    python3 -m ablation.analyzers.cgi_surface_mapper /path/to/rootfs/ --risky-only
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

from ablation.analyzers.shell_sink_classifier import ShellSinkClassifier, ShellSinkResult


_VERDICT_PRIORITY: Dict[str, int] = {
    'ARG_PROPAGATED': 0,
    'EVAL_SINK':      1,
    'UNKNOWN':        2,
    'RODATA_CONST':   3,
    'elf':            4,   # no verdict yet, needs binary RE
    'empty':          5,
}

_ELF_MAGIC = b'\x7fELF'


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class CGIHandler:
    rel_path: str          # relative to cgi root (e.g. "admin/upload_vadp.cgi")
    abs_path: str
    handler_type: str      # "shell" | "elf" | "symlink" | "unknown"
    size: int
    auth_hint: str         # "admin" | "user" | "unknown": inferred from directory name
    max_verdict: str       # worst-case verdict from ShellSinkClassifier (shell only)
    sink_count: int = 0    # number of flagged sinks
    sinks: List[ShellSinkResult] = field(default_factory=list)

    @property
    def priority(self) -> int:
        return _VERDICT_PRIORITY.get(self.max_verdict, 99)

    def one_line(self) -> str:
        verdict_col = self.max_verdict if self.handler_type == 'shell' else f'[{self.handler_type}]'
        return (
            f"{verdict_col:<18} {self.auth_hint:<8} {self.size:>8,}B  {self.rel_path}"
        )


@dataclass
class CGISurface:
    rootfs: str
    cgi_dirs: List[str]
    handlers: List[CGIHandler]

    @property
    def shell_handlers(self) -> List[CGIHandler]:
        return [h for h in self.handlers if h.handler_type == 'shell']

    @property
    def elf_handlers(self) -> List[CGIHandler]:
        return [h for h in self.handlers if h.handler_type == 'elf']

    @property
    def risky(self) -> List[CGIHandler]:
        return [h for h in self.handlers if h.max_verdict in ('ARG_PROPAGATED', 'EVAL_SINK', 'UNKNOWN')]


# ---------------------------------------------------------------------------
# CGISurfaceMapper
# ---------------------------------------------------------------------------

class CGISurfaceMapper:
    """Walk CGI directories in a firmware rootfs and classify every handler."""

    # Common CGI directory paths in embedded Linux firmware
    _CGI_PATHS = (
        'usr/share/www/cgi-bin',
        'var/www/cgi-bin',
        'www/cgi-bin',
        'opt/www/cgi-bin',
        'web/cgi-bin',
        'htdocs/cgi-bin',
        'srv/www/cgi-bin',
        'home/www/cgi-bin',
        'usr/local/www/cgi-bin',
        'usr/bin',    # VIVOTEK: upload_vadp, upload_ttf in /usr/bin
    )

    # Admin/auth indicators in directory names
    _AUTH_DIRS: Set[str] = {'admin', 'auth', 'secure', 'protected', 'private'}
    _USER_DIRS: Set[str] = {'user', 'public', 'guest', 'open'}

    def __init__(self, rootfs: Path, cgi_dirs: Optional[List[str]] = None):
        self._rootfs = rootfs
        self._cgi_dirs = cgi_dirs

    @classmethod
    def from_rootfs(
        cls,
        rootfs: str | Path,
        cgi_dirs: Optional[List[str]] = None,
    ) -> "CGISurfaceMapper":
        return cls(Path(rootfs), cgi_dirs)

    # ------------------------------------------------------------------
    # Main API
    # ------------------------------------------------------------------

    def map(self) -> CGISurface:
        """Walk CGI directories and classify every handler."""
        found_dirs = self._find_cgi_dirs()
        all_handlers: List[CGIHandler] = []

        for cgi_dir in found_dirs:
            for fpath in sorted(cgi_dir.rglob('*')):
                if not fpath.is_file():
                    continue
                handler = self._classify_handler(fpath, cgi_dir)
                if handler:
                    all_handlers.append(handler)

        # Run ShellSinkClassifier on all shell handlers at once
        shell_paths = [
            Path(h.abs_path)
            for h in all_handlers
            if h.handler_type == 'shell'
        ]
        if shell_paths:
            clf = ShellSinkClassifier(shell_paths)
            all_sinks = clf.classify()
            # Index sinks by script path
            sinks_by_path: Dict[str, List[ShellSinkResult]] = {}
            for s in all_sinks:
                sinks_by_path.setdefault(s.script_path, []).append(s)
            # Attach sinks to handlers
            for handler in all_handlers:
                if handler.handler_type != 'shell':
                    continue
                handler_sinks = sinks_by_path.get(handler.abs_path, [])
                handler.sinks = handler_sinks
                handler.sink_count = len(handler_sinks)
                handler.max_verdict = self._worst_verdict(handler_sinks)

        # Sort by priority (worst findings first)
        all_handlers.sort(key=lambda h: (h.priority, h.rel_path))

        return CGISurface(
            rootfs=str(self._rootfs),
            cgi_dirs=[str(d) for d in found_dirs],
            handlers=all_handlers,
        )

    @staticmethod
    def report(surface: CGISurface) -> str:
        lines = [
            f"CGISurfaceMapper: {surface.rootfs}\n",
            f"  CGI dirs found  : {len(surface.cgi_dirs)}\n",
            f"  Total handlers  : {len(surface.handlers)}\n",
            f"  Shell handlers  : {len(surface.shell_handlers)}\n",
            f"  ELF handlers    : {len(surface.elf_handlers)}\n",
            f"  Risky (AP/EVAL/UNK): {len(surface.risky)}\n\n",
            f"{'VERDICT':<18} {'AUTH':<8} {'SIZE':>10}  PATH\n",
            "-" * 80 + "\n",
        ]
        for h in surface.handlers:
            lines.append(h.one_line() + "\n")
            # Show top 3 sinks for risky handlers
            if h.max_verdict in ('ARG_PROPAGATED', 'EVAL_SINK') and h.sinks:
                shown = [s for s in h.sinks if s.verdict in ('ARG_PROPAGATED', 'EVAL_SINK')][:3]
                for s in shown:
                    varinfo = ', '.join(
                        f'{v}={s.var_provenances.get(v, "?")}'
                        for v in s.vars_involved
                    )
                    lines.append(
                        f"    L{s.line_num:<6} {s.sink_type:<10} [{varinfo}]\n"
                        f"      {s.line.strip()[:80]}\n"
                    )
        return ''.join(lines)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _find_cgi_dirs(self) -> List[Path]:
        found: List[Path] = []
        search_paths = (
            [Path(d) for d in self._cgi_dirs]
            if self._cgi_dirs
            else [self._rootfs / p for p in self._CGI_PATHS]
        )
        for d in search_paths:
            if d.is_dir():
                found.append(d)
        return found

    def _classify_handler(self, fpath: Path, cgi_root: Path) -> Optional[CGIHandler]:
        try:
            size = fpath.stat().st_size
        except OSError:
            return None

        rel = str(fpath.relative_to(self._rootfs))
        auth_hint = self._infer_auth(fpath)

        try:
            hdr = fpath.read_bytes()[:16]
        except OSError:
            return None

        if hdr[:4] == _ELF_MAGIC:
            return CGIHandler(
                rel_path=rel, abs_path=str(fpath),
                handler_type='elf', size=size, auth_hint=auth_hint,
                max_verdict='elf',
            )

        # Check for shell shebang or .sh/.cgi extension
        is_shell = (
            hdr[:9] in (b'#!/bin/sh', b'#!/bin/ba')
            or hdr[:10] == b'#!/usr/bin'
            or fpath.suffix in ('.sh', '.cgi')
        )
        if is_shell:
            return CGIHandler(
                rel_path=rel, abs_path=str(fpath),
                handler_type='shell', size=size, auth_hint=auth_hint,
                max_verdict='empty',     # filled in after ShellSinkClassifier run
            )

        # Symlink or other
        if fpath.is_symlink():
            return CGIHandler(
                rel_path=rel, abs_path=str(fpath),
                handler_type='symlink', size=size, auth_hint=auth_hint,
                max_verdict='empty',
            )

        return None

    def _infer_auth(self, fpath: Path) -> str:
        parts = {p.lower() for p in fpath.parts}
        if parts & self._AUTH_DIRS:
            return 'admin'
        if parts & self._USER_DIRS:
            return 'user'
        return 'unknown'

    @staticmethod
    def _worst_verdict(sinks: List[ShellSinkResult]) -> str:
        if not sinks:
            return 'RODATA_CONST'
        priority = {'ARG_PROPAGATED': 0, 'EVAL_SINK': 1, 'UNKNOWN': 2, 'RODATA_CONST': 3}
        return min(sinks, key=lambda s: priority.get(s.verdict, 99)).verdict


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _main() -> None:
    import argparse
    parser = argparse.ArgumentParser(
        description='Map CGI attack surface of an embedded Linux firmware rootfs'
    )
    parser.add_argument('rootfs', help='Path to mounted/extracted rootfs')
    parser.add_argument('--risky-only', action='store_true',
                        help='Show only ARG_PROPAGATED / EVAL_SINK / UNKNOWN handlers')
    args = parser.parse_args()

    mapper = CGISurfaceMapper.from_rootfs(args.rootfs)
    surface = mapper.map()

    if args.risky_only:
        surface.handlers[:] = surface.risky

    print(CGISurfaceMapper.report(surface))


if __name__ == '__main__':
    _main()
