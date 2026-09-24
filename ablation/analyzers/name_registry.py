"""
name_registry.py -- Persistent discovered-function-name overlay for ablation.

Supplements the stripped symbol table: every time an analyst confirms what a
function does, the name is stored here and auto-loaded in future sessions.

Storage: ~/.ablation/function_names.json
Key structure: { sha256_prefix: { va_hex: { "name": str, "source": str, "ts": str } } }

Sources:
  manual    -- analyst assigned the name explicitly
  string    -- name derived from nearby string (auto-inferred)
  confirmed -- finding-confirmed (tied to a disclosed vulnerability)

Usage:
    reg = NameRegistry()
    reg.set_name(binary_sha256, 0x1000, "proto_parse_message", source="confirmed")
    print(reg.get_name(binary_sha256, 0x1000))   # "proto_parse_message"
    reg.save()

    # Via BinaryContext (preferred):
    ctx.set_name(0x1000, "proto_parse_message")
    ctx.name(0x1000)          # "proto_parse_message"
    ctx.names_map()             # {va: name} for all known functions
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

_REGISTRY_PATH = Path.home() / ".ablation" / "function_names.json"


class NameRegistry:
    """Persistent VA->name overlay, keyed by binary SHA256 prefix (16 hex chars)."""

    def __init__(self, path: Optional[Path] = None):
        self._path = path or _REGISTRY_PATH
        # {sha256_16: {va_hex: {"name": str, "source": str, "ts": str}}}
        self._data: Dict[str, Dict[str, dict]] = {}
        self._load()

    # ── public API ────────────────────────────────────────────────────────────

    def get_name(self, sha256: str, va: int) -> Optional[str]:
        """Return the registered name for (sha256, va), or None."""
        key = sha256[:16]
        entry = self._data.get(key, {}).get(f"0x{va:x}")
        return entry["name"] if entry else None

    def set_name(self, sha256: str, va: int, name: str,
                 source: str = "manual") -> None:
        """Register or update a name. Auto-saves to disk."""
        key = sha256[:16]
        self._data.setdefault(key, {})[f"0x{va:x}"] = {
            "name": name,
            "source": source,
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        self.save()

    def delete_name(self, sha256: str, va: int) -> bool:
        """Remove a name. Returns True if it existed."""
        key = sha256[:16]
        va_hex = f"0x{va:x}"
        if key in self._data and va_hex in self._data[key]:
            del self._data[key][va_hex]
            if not self._data[key]:
                del self._data[key]
            self.save()
            return True
        return False

    def all_names(self, sha256: str) -> List[Tuple[int, str, str]]:
        """Return [(va, name, source), ...] sorted by VA for a binary."""
        key = sha256[:16]
        entries = self._data.get(key, {})
        result = []
        for va_hex, rec in entries.items():
            try:
                va = int(va_hex, 16)
                result.append((va, rec["name"], rec.get("source", "manual")))
            except (ValueError, KeyError):
                pass
        return sorted(result)

    def names_map(self, sha256: str) -> Dict[int, str]:
        """Return {va: name} for all registered names for a binary."""
        return {va: name for va, name, _ in self.all_names(sha256)}

    def count(self, sha256: str) -> int:
        return len(self._data.get(sha256[:16], {}))

    # ── persistence ───────────────────────────────────────────────────────────

    def save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(self._data, indent=2, sort_keys=True))

    def _load(self) -> None:
        if self._path.exists():
            try:
                self._data = json.loads(self._path.read_text())
            except Exception:
                self._data = {}


# Module-level singleton -- one registry, shared across all BinaryContext instances.
_registry: Optional[NameRegistry] = None


def get_registry() -> NameRegistry:
    global _registry
    if _registry is None:
        _registry = NameRegistry()
    return _registry
