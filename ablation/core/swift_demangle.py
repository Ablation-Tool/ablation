#!/usr/bin/env python3
"""
Swift Symbol Demangler
Synthesized from: Swift Internals, SE-0235, swift/lib/Demangling

Pure-Python best-effort demangler for Swift 5+ ($s) and legacy Swift 3/4 (_T) symbols.
Falls back to `swift-demangle` binary when available.
"""

import subprocess
import re
from functools import lru_cache

# ── Cache ─────────────────────────────────────────────────────────────────────

_cache: dict[str, str] = {}

# ── Binary availability ───────────────────────────────────────────────────────

def _has_swift_demangle() -> bool:
    try:
        r = subprocess.run(
            ['swift-demangle', '--version'],
            capture_output=True, timeout=3,
        )
        return r.returncode == 0
    except Exception:
        return False

_HAS_SWIFT_DEMANGLE: bool | None = None  # lazy


def _swift_demangle_binary(name: str) -> str | None:
    """Call swift-demangle binary; return result or None on failure."""
    global _HAS_SWIFT_DEMANGLE
    if _HAS_SWIFT_DEMANGLE is None:
        _HAS_SWIFT_DEMANGLE = _has_swift_demangle()
    if not _HAS_SWIFT_DEMANGLE:
        return None
    try:
        r = subprocess.run(
            ['swift-demangle', name],
            capture_output=True, text=True, timeout=5,
        )
        out = r.stdout.strip()
        # swift-demangle echoes the input unchanged if it cannot demangle
        return out if out and out != name else None
    except Exception:
        return None


# ── Known substitutions ───────────────────────────────────────────────────────

# Single-char type codes that appear after a mangling context
_BUILTIN_TYPES: dict[str, str] = {
    'Si': 'Swift.Int',
    'SS': 'Swift.String',
    'Sb': 'Swift.Bool',
    'Sd': 'Swift.Double',
    'Sf': 'Swift.Float',
    'Sv': 'UnsafeRawPointer',
    'So': 'ObjC',
    'Sg': 'Optional',
}

# Known common full-symbol patterns (checked before full parse attempt)
_KNOWN_SUFFIXES: dict[str, str] = {
    'yy': 'Void -> Void',
    'ySS_tF': '(_ arg: String)',
    'ySi_tF': '(_ arg: Int)',
    'ySb_tF': '(_ arg: Bool)',
}


# ── Length-prefixed name reader ───────────────────────────────────────────────

def _read_lp_name(s: str, pos: int) -> tuple[str, int]:
    """
    Read a length-prefixed identifier: e.g. "6MyApp" -> ("MyApp", pos+7).
    Returns ("", pos) on failure.
    """
    start = pos
    while pos < len(s) and s[pos].isdigit():
        pos += 1
    if pos == start:
        return '', start
    length = int(s[start:pos])
    end = pos + length
    if end > len(s):
        return '', start
    return s[pos:end], end


def _read_identifier(s: str, pos: int) -> tuple[str, int]:
    """Read one LP identifier; skip leading underscores in the count region."""
    return _read_lp_name(s, pos)


# ── Context-kind suffixes ─────────────────────────────────────────────────────

_KIND_MAP: dict[str, str] = {
    'C': 'class',
    'V': 'struct',
    'P': 'protocol',
    'E': 'enum',
    'O': 'enum',  # Swift uses O for enum in some contexts
    'F': 'func',
    'M': 'metatype',
}


# ── Pure-Python demangler ─────────────────────────────────────────────────────

def _demangle_swift5(name: str) -> str | None:
    """
    Best-effort pure-Python demangle for Swift 5+ $s symbols.
    Handles common patterns seen in macOS/iOS binaries.
    Returns None when the symbol is not parseable.
    """
    s = name

    # $sSo = ObjC type wrapper
    if s.startswith('$sSo'):
        rest = s[4:]
        ident, _ = _read_lp_name(rest, 0)
        if ident:
            return f'__ObjC.{ident}'
        return '__ObjC type'

    # $ss = Swift standard library symbol
    if s.startswith('$ss'):
        rest = s[3:]
        ident, pos = _read_lp_name(rest, 0)
        if ident:
            kind_char = rest[pos:pos+1]
            kind = _KIND_MAP.get(kind_char, '')
            if kind:
                return f'Swift.{ident} ({kind})'
            return f'Swift.{ident}'
        return 'Swift stdlib symbol'

    # Generic $s<module> path
    if not s.startswith('$s'):
        return None

    body = s[2:]

    # Try to read module name
    module, pos = _read_lp_name(body, 0)
    if not module:
        return None

    parts = [module]
    seen_kind: str | None = None

    # Read type/function identifiers
    max_iters = 8
    for _ in range(max_iters):
        if pos >= len(body):
            break

        ch = body[pos]

        # Check for kind markers that precede identifiers
        if ch in _KIND_MAP:
            seen_kind = _KIND_MAP[ch]
            pos += 1
            ident, new_pos = _read_lp_name(body, pos)
            if ident:
                parts.append(ident)
                pos = new_pos
            continue

        # Digit = start of LP identifier (no kind prefix)
        if ch.isdigit():
            ident, new_pos = _read_lp_name(body, pos)
            if ident:
                parts.append(ident)
                pos = new_pos
                continue
            break

        # Known suffix patterns
        tail = body[pos:]
        for suffix, meaning in _KNOWN_SUFFIXES.items():
            if tail.startswith(suffix):
                result = '.'.join(parts)
                if seen_kind:
                    result += f' ({seen_kind})'
                result += f' {meaning}'
                return result

        # Builtin type shorthands
        for code, typename in _BUILTIN_TYPES.items():
            if tail.startswith(code):
                parts.append(typename)
                pos += len(code)
                break
        else:
            # Unknown single char — skip and stop collecting
            break

    if len(parts) < 2:
        return None

    result = '.'.join(parts)
    if seen_kind:
        result += f' ({seen_kind})'
    return result


def _demangle_legacy(name: str) -> str | None:
    """
    Best-effort demangle for Swift 3/4 _T symbols.
    Format: _T<module><type><...>
    Returns None when not recognisably parseable.
    """
    if not name.startswith('_T'):
        return None

    body = name[2:]

    # _TM = metadata; _Tf = function; _Tv = variable
    if not body:
        return 'Swift legacy symbol'

    prefix_kind = {
        'M': 'metadata',
        'f': 'func',
        'v': 'var',
        'F': 'func',
        'C': 'class',
        'V': 'struct',
        'P': 'protocol',
    }

    parts: list[str] = []
    pos = 0

    kind = prefix_kind.get(body[0])
    if kind:
        pos = 1

    for _ in range(6):
        if pos >= len(body):
            break
        if body[pos].isdigit():
            ident, new_pos = _read_lp_name(body, pos)
            if ident:
                parts.append(ident)
                pos = new_pos
                continue
        break

    if parts:
        result = '.'.join(parts)
        if kind:
            result += f' ({kind})'
        return result
    return 'Swift 3/4 symbol'


# ── Public API ────────────────────────────────────────────────────────────────

def is_swift_symbol(name: str) -> bool:
    """Return True if name is a Swift mangled symbol."""
    if not name:
        return False
    return (
        name.startswith('$s')
        or name.startswith('$S')
        or name.startswith('_T')
        or name.startswith('$sSo')
        or name.startswith('$ss')
    )


def demangle(name: str) -> str:
    """
    Demangle a Swift symbol to human-readable form.
    Order: cache -> swift-demangle binary -> pure-Python -> original.
    """
    if not name:
        return name

    if name in _cache:
        return _cache[name]

    result: str | None = None

    # 1. Try binary first — most accurate
    result = _swift_demangle_binary(name)

    # 2. Fall back to pure-Python
    if result is None:
        if name.startswith('$s') or name.startswith('$S'):
            result = _demangle_swift5(name)
        elif name.startswith('_T'):
            result = _demangle_legacy(name)

    # 3. Give up — return original
    if result is None:
        result = name

    _cache[name] = result
    return result


def demangle_batch(names: list) -> dict:
    """
    Demangle a list of mangled names.
    Returns {mangled: demangled}.
    Batches against swift-demangle when available for efficiency.
    """
    if not names:
        return {}

    result: dict[str, str] = {}

    # Separate already-cached from uncached
    uncached = [n for n in names if n not in _cache]
    for n in names:
        if n in _cache:
            result[n] = _cache[n]

    if not uncached:
        return result

    # Try batch binary call
    global _HAS_SWIFT_DEMANGLE
    if _HAS_SWIFT_DEMANGLE is None:
        _HAS_SWIFT_DEMANGLE = _has_swift_demangle()

    if _HAS_SWIFT_DEMANGLE:
        try:
            r = subprocess.run(
                ['swift-demangle'] + uncached,
                capture_output=True, text=True, timeout=30,
            )
            if r.returncode == 0:
                lines = r.stdout.strip().splitlines()
                # swift-demangle outputs one demangled name per line
                for name, line in zip(uncached, lines):
                    demangled = line.strip()
                    if demangled and demangled != name:
                        _cache[name] = demangled
                        result[name] = demangled
                    else:
                        # Binary couldn't demangle — try pure-Python
                        py_result = demangle(name)
                        result[name] = py_result
                # Handle count mismatch (binary skipped some)
                for name in uncached:
                    if name not in result:
                        result[name] = demangle(name)
                return result
        except Exception:
            pass

    # Pure-Python fallback for all uncached
    for name in uncached:
        result[name] = demangle(name)

    return result
