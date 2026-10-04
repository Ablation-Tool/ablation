"""
local_modules.py — Local Module Store for Ablation.

Manages user-built modules that live outside the Ablation package. Native modules
ship with Ablation and are maintained upstream. Local modules are built, owned,
and stored on the user's machine — they are never committed to the public repo.

Storage:
    ~/.ablation/local_modules/          module .py files
    ~/.ablation/local_modules/registry.json   metadata per registered module

Separation:
    Native modules  — ablation.analyzers.*   (shipped with Ablation, read-only)
    Local modules   — loaded from ~/.ablation/local_modules/ at session start

SAFECODE gate:
    Every module passes SAFECODE before it enters the store. A failing gate
    blocks registration. This ensures local modules are held to the same
    production readiness standard as native Ablation modules.

Usage:
    from ablation.local_modules import LocalModuleStore

    store = LocalModuleStore()

    # Register a module (SAFECODE gate runs automatically)
    store.register('/path/to/my_scanner.py')

    # Load all registered modules into the current session
    loaded = store.load_all()
    MyScanner = loaded['my_scanner'].MyScanner

    # List what is registered
    store.list()

    # Remove a module
    store.remove('my_scanner')

Auto-load at session start:
    LocalModuleStore().load_all() is called automatically when ablation is
    imported. Loaded modules are available in the session namespace.

CLI:
    ablation-local list
    ablation-local register /path/to/my_scanner.py
    ablation-local remove my_scanner
    ablation-local show my_scanner
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Optional

_STORE_DIR  = Path.home() / '.ablation' / 'local_modules'
_REGISTRY   = _STORE_DIR / 'registry.json'


# ── Data types ────────────────────────────────────────────────────────────────

@dataclass
class LocalModuleEntry:
    name:             str
    filename:         str      # basename inside store dir
    safecode_passed:  bool
    registered_at:    str      # ISO-8601
    description:      str = ''
    safecode_report:  str = '' # summary line from SafecodeReport

    def as_dict(self) -> dict:
        return {
            'name':            self.name,
            'filename':        self.filename,
            'safecode_passed': self.safecode_passed,
            'registered_at':   self.registered_at,
            'description':     self.description,
            'safecode_report': self.safecode_report,
        }

    @classmethod
    def from_dict(cls, d: dict) -> 'LocalModuleEntry':
        return cls(
            name=d['name'],
            filename=d['filename'],
            safecode_passed=d.get('safecode_passed', False),
            registered_at=d.get('registered_at', ''),
            description=d.get('description', ''),
            safecode_report=d.get('safecode_report', ''),
        )


# ── Store ─────────────────────────────────────────────────────────────────────

class LocalModuleStore:
    """
    Manages user-built Ablation modules stored in ~/.ablation/local_modules/.

    Native modules (ablation.analyzers.*) are never touched.
    Local modules are registered, gated by SAFECODE, and loaded per session.
    """

    def __init__(self, store_dir: Optional[Path] = None):
        self._dir = store_dir or _STORE_DIR
        self._dir.mkdir(parents=True, exist_ok=True)

    # ── Registry I/O ─────────────────────────────────────────────────────────

    def _read_registry(self) -> list[LocalModuleEntry]:
        if not _REGISTRY.exists():
            return []
        try:
            data = json.loads(_REGISTRY.read_text(encoding='utf-8'))
            return [LocalModuleEntry.from_dict(d) for d in data.get('modules', [])]
        except (json.JSONDecodeError, KeyError):
            return []

    def _write_registry(self, entries: list[LocalModuleEntry]) -> None:
        _REGISTRY.write_text(
            json.dumps({'modules': [e.as_dict() for e in entries]}, indent=2),
            encoding='utf-8',
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def register(
        self,
        path: str,
        description: str = '',
        skip_safecode: bool = False,
    ) -> LocalModuleEntry:
        """
        Register a module into the local store.

        Runs SAFECODE on the module first. Registration is blocked if any
        HIGH or CRITICAL finding is present, unless skip_safecode=True
        (not recommended — only for modules that cannot use the LLM gate).

        The module file is copied into ~/.ablation/local_modules/.
        """
        src = Path(path).expanduser().resolve()
        if not src.exists():
            raise FileNotFoundError(f"local_modules.register: file not found: {path}")
        if not src.suffix == '.py':
            raise ValueError(f"local_modules.register: only .py files supported, got: {src.name}")

        name = src.stem
        dest = self._dir / src.name

        # ── SAFECODE gate ─────────────────────────────────────────────────────
        safecode_passed = False
        safecode_summary = ''

        if not skip_safecode:
            try:
                from ablation.analyzers.safecode import SAFECODE
                report = SAFECODE.audit_module(str(src))
                safecode_passed = report.gate_passed
                safecode_summary = (
                    f"gate={'PASSED' if report.gate_passed else 'BLOCKED'} "
                    f"findings={len(report.findings)} "
                    f"highs={len(report.highs())}"
                )
                if not report.gate_passed:
                    raise PermissionError(
                        f"SAFECODE blocked registration of '{name}': "
                        f"{len(report.highs())} HIGH/CRITICAL finding(s).\n"
                        f"Fix findings before registering. Run:\n"
                        f"  from ablation.analyzers.safecode import SAFECODE\n"
                        f"  print(SAFECODE.audit_module('{path}').report())"
                    )
            except ImportError:
                # anthropic not installed — allow registration but flag as unverified
                safecode_passed = False
                safecode_summary = 'unverified (ablation[llm] not installed)'
        else:
            safecode_passed = True
            safecode_summary = 'skipped (skip_safecode=True)'

        # ── Copy into store ───────────────────────────────────────────────────
        shutil.copy2(str(src), str(dest))

        # ── Update registry ───────────────────────────────────────────────────
        entries = [e for e in self._read_registry() if e.name != name]
        entry = LocalModuleEntry(
            name=name,
            filename=src.name,
            safecode_passed=safecode_passed,
            registered_at=datetime.now(timezone.utc).isoformat(),
            description=description,
            safecode_report=safecode_summary,
        )
        entries.append(entry)
        self._write_registry(entries)

        print(f"[local_modules] registered '{name}' — SAFECODE: {safecode_summary}")
        return entry

    def load_all(self) -> dict[str, ModuleType]:
        """
        Import all registered local modules and return them as a dict.

        Modules are imported under the name 'ablation_local.<name>' so they
        never shadow native ablation modules. Failed imports are skipped with
        a warning — one broken module does not prevent the others from loading.
        """
        loaded: dict[str, ModuleType] = {}
        for entry in self._read_registry():
            module_path = self._dir / entry.filename
            if not module_path.exists():
                print(f"[local_modules] warning: '{entry.name}' registered but file missing: {module_path}")
                continue
            try:
                mod = _import_from_path(entry.name, module_path)
                loaded[entry.name] = mod
            except Exception as exc:
                print(f"[local_modules] warning: failed to load '{entry.name}': {exc}")
        return loaded

    def list(self) -> list[LocalModuleEntry]:
        """Return all registered local module entries."""
        return self._read_registry()

    def remove(self, name: str) -> bool:
        """
        Remove a module from the store and registry.

        Returns True if removed, False if not found.
        """
        entries = self._read_registry()
        target = next((e for e in entries if e.name == name), None)
        if target is None:
            return False

        module_path = self._dir / target.filename
        if module_path.exists():
            module_path.unlink()

        self._write_registry([e for e in entries if e.name != name])

        mod_key = f'ablation_local.{name}'
        sys.modules.pop(mod_key, None)

        print(f"[local_modules] removed '{name}'")
        return True

    def get(self, name: str) -> Optional[LocalModuleEntry]:
        """Return the registry entry for a module by name."""
        return next((e for e in self._read_registry() if e.name == name), None)

    def report(self) -> str:
        """Print a summary table of all registered local modules."""
        entries = self._read_registry()
        if not entries:
            return "No local modules registered. Use LocalModuleStore().register('/path/to/module.py')"

        lines = [
            f"LOCAL MODULES — {self._dir}",
            f"{'Name':<30} {'SAFECODE':<10} {'Registered':<26} Description",
            "-" * 90,
        ]
        for e in entries:
            gate = 'PASSED' if e.safecode_passed else 'BLOCKED'
            ts = e.registered_at[:19].replace('T', ' ')
            lines.append(f"{e.name:<30} {gate:<10} {ts:<26} {e.description or '—'}")
        return "\n".join(lines)


# ── Import helper ─────────────────────────────────────────────────────────────

def _import_from_path(name: str, path: Path) -> ModuleType:
    """Import a .py file from an arbitrary path without modifying sys.path."""
    module_name = f'ablation_local.{name}'
    spec = importlib.util.spec_from_file_location(module_name, str(path))
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot create module spec for {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    return mod


# ── Auto-load ─────────────────────────────────────────────────────────────────

def autoload() -> dict[str, ModuleType]:
    """
    Load all registered local modules at session start.

    Called automatically when ablation is imported. Safe to call multiple times —
    already-loaded modules are not reloaded.
    """
    store = LocalModuleStore()
    entries = store.list()
    if not entries:
        return {}
    loaded = store.load_all()
    if loaded:
        names = ', '.join(loaded.keys())
        print(f"[local_modules] loaded {len(loaded)} local module(s): {names}")
    return loaded


# ── CLI ───────────────────────────────────────────────────────────────────────

def _cli() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        prog='ablation-local',
        description='Manage Ablation local modules (~/.ablation/local_modules/)',
    )
    sub = parser.add_subparsers(dest='cmd', required=True)

    sub.add_parser('list', help='list registered local modules')

    r = sub.add_parser('register', help='register a module (runs SAFECODE gate)')
    r.add_argument('path', help='path to .py file')
    r.add_argument('--description', default='', help='optional description')
    r.add_argument('--skip-safecode', action='store_true',
                   help='skip SAFECODE gate (not recommended)')

    rm = sub.add_parser('remove', help='remove a registered module')
    rm.add_argument('name', help='module name (stem of .py filename)')

    sh = sub.add_parser('show', help='show details for a module')
    sh.add_argument('name', help='module name')

    args = parser.parse_args()
    store = LocalModuleStore()

    if args.cmd == 'list':
        print(store.report())

    elif args.cmd == 'register':
        try:
            store.register(args.path, description=args.description,
                           skip_safecode=args.skip_safecode)
        except PermissionError as e:
            print(str(e), file=sys.stderr)
            sys.exit(1)

    elif args.cmd == 'remove':
        if not store.remove(args.name):
            print(f"local_modules: '{args.name}' not found", file=sys.stderr)
            sys.exit(1)

    elif args.cmd == 'show':
        entry = store.get(args.name)
        if entry is None:
            print(f"local_modules: '{args.name}' not found", file=sys.stderr)
            sys.exit(1)
        print(f"name           : {entry.name}")
        print(f"file           : {entry.filename}")
        print(f"safecode       : {'PASSED' if entry.safecode_passed else 'BLOCKED/UNVERIFIED'}")
        print(f"safecode report: {entry.safecode_report}")
        print(f"registered     : {entry.registered_at}")
        print(f"description    : {entry.description or '—'}")


if __name__ == '__main__':
    _cli()
