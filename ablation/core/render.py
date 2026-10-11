"""
render.py: Colored terminal output primitives for Ablation.

Detects terminal color support at import time (truecolor / ansi256 / ansi16 / plain).
All color constants are empty strings in plain mode so callers need no mode checks.
"""

from __future__ import annotations

import os
import re
import sys


# ── Mode detection ─────────────────────────────────────────────────────────────

def _detect_mode() -> str:
    try:
        tty = sys.stdout.isatty()
    except Exception:
        return 'plain'
    if not tty:
        return 'plain'
    if os.environ.get('NO_COLOR'):
        return 'plain'
    ct = os.environ.get('COLORTERM', '').lower()
    if ct in ('truecolor', '24bit'):
        return 'truecolor'
    if '256color' in os.environ.get('TERM', ''):
        return 'ansi256'
    return 'ansi16'


MODE: str = _detect_mode()


# ── Color constants ────────────────────────────────────────────────────────────

def _pick(tc: str, a256: str, a16: str) -> str:
    if MODE == 'truecolor': return tc
    if MODE == 'ansi256':   return a256
    if MODE == 'ansi16':    return a16
    return ''


def _tc(r: int, g: int, b: int) -> str:
    return f'\033[38;2;{r};{g};{b}m'


def _256(n: int) -> str:
    return f'\033[38;5;{n}m'


RESET  = '\033[0m'  if MODE != 'plain' else ''
BOLD   = '\033[1m'  if MODE != 'plain' else ''
DIM    = '\033[2m'  if MODE != 'plain' else ''

RED    = _pick(_tc(220, 50,  47),  _256(196), '\033[31m')
ORANGE = _pick(_tc(220, 130, 20),  _256(208), '\033[33m')
YELLOW = _pick(_tc(181, 137, 0),   _256(178), '\033[33m')
GREEN  = _pick(_tc(88,  166, 92),  _256(71),  '\033[32m')
BLUE   = _pick(_tc(38,  139, 210), _256(33),  '\033[34m')
PURPLE = _pick(_tc(130, 100, 220), _256(135), '\033[35m')
GRAY   = _pick(_tc(120, 130, 140), _256(244), '\033[37m')
WHITE  = _pick(_tc(220, 220, 220), _256(255), '\033[97m')


# ── Helpers ────────────────────────────────────────────────────────────────────

_ANSI_RE = re.compile(r'\033\[[^m]*m')

def strip(s: str) -> str:
    """Remove all ANSI escape sequences — use to compute display widths."""
    return _ANSI_RE.sub('', s)


_DEFAULT_WIDTH = 68


# ── Drawing functions ──────────────────────────────────────────────────────────

def box(lines: list[str], color: str = '', width: int = _DEFAULT_WIDTH) -> str:
    """Double-border box. Use for top-level containers."""
    c = color or WHITE
    top = c + '╔' + '═' * (width - 2) + '╗' + RESET
    bot = c + '╚' + '═' * (width - 2) + '╝' + RESET
    rows = []
    for line in lines:
        pad = width - 2 - len(strip(line))
        rows.append(c + '║' + RESET + ' ' + line + ' ' * max(0, pad - 1) + c + '║' + RESET)
    return '\n'.join([top] + rows + [bot])


def sbox(lines: list[str], color: str = '', width: int = _DEFAULT_WIDTH) -> str:
    """Single-border box. Use for data blocks and reports."""
    c = color or GRAY
    top = c + '┌' + '─' * (width - 2) + '┐' + RESET
    bot = c + '└' + '─' * (width - 2) + '┘' + RESET
    rows = []
    for line in lines:
        pad = width - 2 - len(strip(line))
        rows.append(c + '│' + RESET + ' ' + line + ' ' * max(0, pad - 1) + c + '│' + RESET)
    return '\n'.join([top] + rows + [bot])


def section(title: str, color: str = '', width: int = _DEFAULT_WIDTH) -> str:
    """Horizontal rule with a title. Use for layer and section headers."""
    c = color or GRAY
    bar = '─' * max(0, width - len(strip(title)) - 2)
    return c + title + (' ' + bar if bar else '') + RESET


def arrow(label: str = '', color: str = '') -> str:
    """Vertical arrow stem with an optional inline label."""
    c = color or GRAY
    if label:
        return c + '  │' + RESET + DIM + f'  {label}' + RESET
    return c + '  │' + RESET


def arrowdown(color: str = '') -> str:
    """Downward arrowhead."""
    c = color or GRAY
    return c + '  ▼' + RESET
