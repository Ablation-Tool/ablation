"""
vendor_profile.py: load vendor-specific sink registrations and known-safe
exec patterns from YAML profiles in ablation/profiles/.

Usage:
    from ablation.analyzers.vendor_profile import VendorProfile
    from ablation.analyzers.sink_arg_classifier import SinkArgClassifier

    clf  = SinkArgClassifier.from_path('/path/to/binary')
    prof = VendorProfile.from_vendor('fortinet')
    prof.apply_to(clf)
    results = clf.classify_all()

Profile format (ablation/profiles/<vendor>.yaml):
    vendor: <name>
    sinks:
      - name: <symbol_name>       # PLT symbol to register as a sink
        arg_pos: <int>            # 0=rdi, 1=rsi, 2=rdx, ...
        note: <explanation>
    known_safe_exec_patterns:
      - id: <pattern_id>
        description: <why it is safe>
        fingerprint:
          unsetenv_strings: [...]  # env vars cleared immediately before execvp
        verdict: ELIMINATED
        seen_in: [...]
    known_sanitizers:
      - name: <symbol_name>
        charset: <regex-like description>
        note: <explanation>

The VendorProfile does NOT auto-eliminate findings — it pre-registers sinks
so the classifier can find them, and provides reference data for post-classification
annotation.  known_safe_exec_patterns are for documentation and future automation.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

_PROFILES_DIR = Path(__file__).parent.parent / 'profiles'

_YAML_OK = False
try:
    import yaml as _yaml
    _YAML_OK = True
except ImportError:
    pass


class VendorProfile:
    """
    Vendor-specific sink registry and architecture knowledge for ablation analyzers.

    Attributes:
        vendor:           Vendor name (e.g. 'fortinet').
        sinks:            List of {'name', 'arg_pos', 'note'} dicts.
        safe_patterns:    List of known-safe exec pattern records.
        sanitizers:       List of known sanitizer function records.
    """

    def __init__(self, data: Dict[str, Any]):
        self.vendor:        str        = data.get('vendor', 'unknown')
        self.sinks:         List[dict] = data.get('sinks', [])
        self.safe_patterns: List[dict] = data.get('known_safe_exec_patterns', [])
        self.sanitizers:    List[dict] = data.get('known_sanitizers', [])

    # ── factories ─────────────────────────────────────────────────────────────

    @classmethod
    def from_vendor(cls, vendor: str) -> 'VendorProfile':
        """Load profile by vendor name (e.g. 'fortinet' → profiles/fortinet.yaml)."""
        if not _YAML_OK:
            raise ImportError(
                'PyYAML is required for VendorProfile: pip install pyyaml'
            )
        path = _PROFILES_DIR / f'{vendor.lower()}.yaml'
        if not path.exists():
            raise FileNotFoundError(
                f'No vendor profile found for {vendor!r} (expected {path})'
            )
        with path.open() as f:
            data = _yaml.safe_load(f)
        return cls(data)

    @classmethod
    def from_path(cls, path: str) -> 'VendorProfile':
        """Load profile from an explicit YAML file path."""
        if not _YAML_OK:
            raise ImportError(
                'PyYAML is required for VendorProfile: pip install pyyaml'
            )
        with open(path) as f:
            data = _yaml.safe_load(f)
        return cls(data)

    @classmethod
    def available_vendors(cls) -> List[str]:
        """Return list of vendor names with available profiles."""
        if not _PROFILES_DIR.exists():
            return []
        return [p.stem for p in _PROFILES_DIR.glob('*.yaml')]

    # ── application ───────────────────────────────────────────────────────────

    def apply_to(self, classifier) -> None:
        """
        Register all vendor sinks into a SinkArgClassifier instance.

        Calls classifier.add_sink(name, arg_pos) for each registered sink.
        No-ops if the sink's symbol is not present in the binary's PLT.
        """
        for sink in self.sinks:
            name    = sink.get('name', '')
            arg_pos = sink.get('arg_pos', 0)
            if name:
                classifier.add_sink(name, arg_pos)

    def sink_note(self, name: str) -> str:
        """Return the note for a named sink, or '' if not found."""
        for s in self.sinks:
            if s.get('name') == name:
                return s.get('note', '')
        return ''

    def safe_pattern_for_exec(self, unsetenv_strings: List[str]) -> Optional[dict]:
        """
        Look up a known_safe_exec_pattern by matching unsetenv fingerprint strings.

        Returns the matching pattern record, or None if no match.
        """
        for pat in self.safe_patterns:
            fp = pat.get('fingerprint', {})
            required = fp.get('unsetenv_strings', [])
            if required and all(s in unsetenv_strings for s in required):
                return pat
        return None

    # ── reporting ─────────────────────────────────────────────────────────────

    def summary(self) -> str:
        lines = [f'VendorProfile: {self.vendor}']
        lines.append(f'  Sinks ({len(self.sinks)}):')
        for s in self.sinks:
            lines.append(f'    {s["name"]:30s}  arg{s["arg_pos"]}  {s.get("note","")[:60]}')
        if self.safe_patterns:
            lines.append(f'  Known-safe exec patterns ({len(self.safe_patterns)}):')
            for p in self.safe_patterns:
                lines.append(f'    [{p["id"]}]  {p.get("verdict","")}  {p.get("description","")[:60]}')
        if self.sanitizers:
            lines.append(f'  Known sanitizers ({len(self.sanitizers)}):')
            for san in self.sanitizers:
                lines.append(f'    {san["name"]:30s}  charset={san.get("charset","")}')
        return '\n'.join(lines)
