"""Tests for SigLibrary -- function signature loading and matching (no model required)."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


def test_signatures_load():
    from ablation.analyzers.sig_library import SigLibrary
    lib = SigLibrary()
    sigs = lib.known_signatures()
    assert len(sigs) >= 20


def test_signature_has_required_fields():
    from ablation.analyzers.sig_library import SigLibrary
    lib = SigLibrary()
    for sig in lib.known_signatures():
        assert 'name' in sig
        assert 'description' in sig
        assert isinstance(sig['description'], str)
        assert len(sig['description']) > 10


def test_signatures_include_key_functions():
    from ablation.analyzers.sig_library import SigLibrary
    lib = SigLibrary()
    names = {s['name'] for s in lib.known_signatures()}
    for expected in ('memcpy', 'malloc', 'strlen', 'recv', 'system'):
        assert expected in names, f"Missing signature for {expected}"


def test_sigs_json_ships_with_package():
    """Verify sigs.json is co-located with the package data."""
    from pathlib import Path
    import ablation
    pkg_root = Path(ablation.__file__).parent
    sigs_file = pkg_root / 'data' / 'sigs.json'
    assert sigs_file.exists(), f"sigs.json not found at {sigs_file}"


def test_match_function_skips_named():
    """match_function should skip functions that already have real names."""
    from ablation.analyzers.sig_library import SigLibrary
    lib = SigLibrary()
    # A function named 'parse_header' should not be matched (it's already named)
    result = lib.match_function('parse_header', '[]', '[]', '')
    assert result is None


def test_match_function_skips_empty():
    """match_function on a placeholder with no signal should return None."""
    from ablation.analyzers.sig_library import SigLibrary
    lib = SigLibrary()
    result = lib.match_function('fn_0x1000', '[]', '[]', '')
    assert result is None
